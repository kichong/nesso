import assert from 'node:assert/strict'
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test, { type TestContext } from 'node:test'
import { createAiConnections } from './ai-connections/index.ts'
import { createAiStorage } from './ai-storage.ts'
import { ElectronError } from './errors.ts'

const fixture = (context: TestContext) => {
  const directory = mkdtempSync(path.join(tmpdir(), 'nesso-ai-'))
  context.after(() => rmSync(directory, { recursive: true, force: true }))
  const file = path.join(directory, 'ai-connections.enc')
  const key = randomBytes(32)
  const encryption = {
    isEncryptionAvailable: context.mock.fn(() => true),
    getSelectedStorageBackend: () => 'gnome_libsecret' as const,
    encryptString: context.mock.fn((value: string) => {
      const iv = randomBytes(12)
      const cipher = createCipheriv('aes-256-gcm', key, iv)
      const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()])
      return Buffer.concat([iv, cipher.getAuthTag(), encrypted])
    }),
    decryptString: context.mock.fn((value: Buffer) => {
      const decipher = createDecipheriv('aes-256-gcm', key, value.subarray(0, 12))
      decipher.setAuthTag(value.subarray(12, 28))
      return Buffer.concat([decipher.update(value.subarray(28)), decipher.final()]).toString('utf8')
    }),
  }
  return { directory, file, encryption, storage: createAiStorage(file, encryption) }
}
const input = {
  name: 'OpenAI',
  provider: 'openai' as const,
  endpoint: 'https://api.openai.com/v1',
  model: 'model',
  apiKey: 'secret',
}
const legacyRecord = {
  connections: [{ ...input, id: 'synthetic-connection' }],
  activeId: 'synthetic-connection',
}
const legacyFixture = (context: TestContext) => {
  const result = fixture(context)
  const raw = JSON.stringify(legacyRecord, null, 2)
  const original = result.encryption.encryptString(raw)
  writeFileSync(result.file, original, { mode: 0o600 })
  const backup = `${result.file}.backup-${createHash('sha256').update(original).digest('hex')}`
  result.encryption.encryptString.mock.resetCalls()
  return { ...result, raw, original, backup }
}

test('secure storage is accessed only when saving or reading existing credentials', async (context) => {
  const { file, encryption, storage } = fixture(context)
  const connections = createAiConnections(storage)
  assert.deepEqual(connections.list(), { connections: [], activeId: null, accounts: [] })
  assert.equal(encryption.isEncryptionAvailable.mock.callCount(), 0)
  connections.save(input)
  assert.equal(encryption.isEncryptionAvailable.mock.callCount(), 1)
  const restarted = createAiConnections(createAiStorage(file, encryption))
  assert.equal(encryption.isEncryptionAvailable.mock.callCount(), 1)
  assert.equal(encryption.decryptString.mock.callCount(), 0)
  assert.equal((await restarted.active()).apiKey, input.apiKey)
  assert.equal(encryption.decryptString.mock.callCount(), 1)
})

test('unavailable encryption and insecure Linux backends preserve existing connections', (context) => {
  const { directory, file, encryption, original } = legacyFixture(context)
  for (const unavailable of [
    createAiStorage(file, { ...encryption, isEncryptionAvailable: () => false }),
    createAiStorage(
      file,
      { ...encryption, getSelectedStorageBackend: () => 'basic_text' },
      'linux',
    ),
  ]) {
    assert.throws(() => unavailable.read(), ElectronError)
    assert.throws(() => unavailable.write('replacement'), ElectronError)
    assert.throws(() => unavailable.upgrade('replacement'), ElectronError)
    assert.throws(() => createAiConnections(unavailable).list(), ElectronError)
  }
  assert.deepEqual(readFileSync(file), original)
  assert.deepEqual(readdirSync(directory), [path.basename(file)])
})

test('upgrades preserve exact encrypted originals privately and leave current records unchanged on subsequent reads', (context) => {
  const { directory, file, encryption, storage, original, backup, raw } = legacyFixture(context)
  const connections = createAiConnections(storage)
  assert.equal(connections.list().activeId, legacyRecord.activeId)
  assert.deepEqual(readFileSync(backup), original)
  assert.equal(encryption.decryptString(readFileSync(backup)), raw)
  assert.deepEqual(JSON.parse(storage.read()!), { ...legacyRecord, version: 1 })
  assert.notDeepEqual(readFileSync(file), original)
  assert.deepEqual(
    readdirSync(directory).sort(),
    [path.basename(file), path.basename(backup)].sort(),
  )
  const upgraded = readFileSync(file)
  assert.equal(createAiConnections(createAiStorage(file, encryption)).list().connections.length, 1)
  assert.deepEqual(readFileSync(file), upgraded)
  assert.equal(encryption.encryptString.mock.callCount(), 1)
  for (const name of readdirSync(directory)) {
    const saved = path.join(directory, name)
    assert.equal(readFileSync(saved).includes(Buffer.from(input.apiKey)), false)
    if (process.platform !== 'win32') assert.equal(statSync(saved).mode & 0o777, 0o600)
  }
})

test('backup, encryption and write failures protect credentials and allow retrying after restart', (context) => {
  const { directory, file, encryption, storage, original, backup } = legacyFixture(context)
  const connections = createAiConnections(storage)
  mkdirSync(backup)
  assert.throws(() => connections.list(), ElectronError)
  assert.deepEqual(readFileSync(file), original)
  assert.equal(encryption.encryptString.mock.callCount(), 0)
  rmSync(backup, { recursive: true })

  let preservedAtEncryption: Buffer | undefined
  encryption.encryptString.mock.mockImplementationOnce(() => {
    preservedAtEncryption = readFileSync(backup)
    throw new Error('Synthetic encryption failure')
  })
  assert.throws(() => connections.list(), ElectronError)
  assert.deepEqual(preservedAtEncryption, original)
  assert.deepEqual(readFileSync(file), original)
  assert.deepEqual(readFileSync(backup), original)

  mkdirSync(`${file}.tmp`)
  assert.throws(() => connections.save({ ...input, name: 'Changed' }), ElectronError)
  assert.deepEqual(readFileSync(file), original)
  assert.deepEqual(readFileSync(backup), original)
  rmSync(`${file}.tmp`, { recursive: true })
  assert.equal(
    createAiConnections(createAiStorage(file, encryption)).list().activeId,
    legacyRecord.activeId,
  )
  assert.deepEqual(JSON.parse(storage.read()!), { ...legacyRecord, version: 1 })
  assert.deepEqual(readFileSync(backup), original)
  assert.equal(readdirSync(directory).length, 2)
})
