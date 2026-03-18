import {
  error as coreError,
  getInput,
  getState,
  info,
  saveState,
  setFailed,
  setOutput,
  setSecret
} from '@actions/core'
import axios, {isAxiosError} from 'axios'
import {existsSync, readFileSync, writeFileSync} from 'fs'
import {platform} from 'os'
import {fileSync} from 'tmp'
import {deleteKeychain, installCertIntoTemporaryKeychain} from './security'

async function validateSubscription() {
  let repoPrivate
  const eventPath = process.env.GITHUB_EVENT_PATH
  if (eventPath && existsSync(eventPath)) {
    const payload = JSON.parse(readFileSync(eventPath, 'utf8'))
    repoPrivate = payload?.repository?.private
  }
  const upstream = 'oven-sh/setup-bun'
  const action = process.env.GITHUB_ACTION_REPOSITORY
  const docsUrl =
    'https://docs.stepsecurity.io/actions/stepsecurity-maintained-actions'

  info('')
  info('\u001b[1;36mStepSecurity Maintained Action\u001b[0m')
  info(`Secure drop-in replacement for ${upstream}`)
  if (repoPrivate === false)
    info('\u001b[32m\u2713 Free for public repositories\u001b[0m')
  info(`\u001b[36mLearn more:\u001b[0m ${docsUrl}`)
  info('')

  if (repoPrivate === false) return

  const serverUrl = process.env.GITHUB_SERVER_URL || 'https://github.com'
  const body: Record<string, string> = {action: action || ''}
  if (serverUrl !== 'https://github.com') body.ghes_server = serverUrl
  try {
    await axios.post(
      `https://agent.api.stepsecurity.io/v1/github/${process.env.GITHUB_REPOSITORY}/actions/maintained-actions-subscription`,
      body,
      {timeout: 3000}
    )
  } catch (error) {
    if (isAxiosError(error) && error.response?.status === 403) {
      coreError(
        `\u001b[1;31mThis action requires a StepSecurity subscription for private repositories.\u001b[0m`
      )
      coreError(
        `\u001b[31mLearn how to enable a subscription: ${docsUrl}\u001b[0m`
      )
      process.exit(1)
    }
    info('Timeout or API not reachable. Continuing to next step.')
  }
}

async function run(): Promise<void> {
  try {
    await validateSubscription()
    if (platform() !== 'darwin') {
      throw new Error('Action requires macOS agent.')
    }

    const keychain: string = getInput('keychain')
    const createKeychain: boolean = getInput('create-keychain') === 'true'
    let keychainPassword: string = getInput('keychain-password')
    let p12Filepath: string = getInput('p12-filepath')
    const p12FileBase64: string = getInput('p12-file-base64')
    const p12Password: string = getInput('p12-password')

    if (p12Filepath === '' && p12FileBase64 === '') {
      throw new Error(
        'At least one of p12-filepath or p12-file-base64 must be provided'
      )
    }

    if (p12FileBase64 !== '') {
      const buffer = Buffer.from(p12FileBase64, 'base64')
      const tempFile = fileSync()
      p12Filepath = tempFile.name
      writeFileSync(p12Filepath, buffer)
    }

    if (keychainPassword === '') {
      // generate a keychain password for the temporary keychain
      keychainPassword = Math.random().toString(36)
    }

    setOutput('keychain-password', keychainPassword)
    setSecret(keychainPassword)

    await installCertIntoTemporaryKeychain(
      keychain,
      createKeychain,
      keychainPassword,
      p12Filepath,
      p12Password
    )
  } catch (error) {
    if (error instanceof Error) {
      setFailed(error.message)
    } else {
      setFailed(`Action failed with error ${error}`)
    }
  }
}

async function cleanup(): Promise<void> {
  try {
    const keychain: string = getInput('keychain')
    const didCreateKeychain: boolean = getInput('create-keychain') === 'true'

    // only delete the keychain if it was created by this action
    if (didCreateKeychain) {
      await deleteKeychain(keychain)
    }
  } catch (error) {
    if (error instanceof Error) {
      setFailed(error.message)
    } else {
      setFailed(`Action failed with error ${error}`)
    }
  }
}

if (getState('isPost')) {
  cleanup()
} else {
  saveState('isPost', 'true')
  run()
}
