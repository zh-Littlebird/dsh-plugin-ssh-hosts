import assert from 'node:assert/strict'
import test from 'node:test'
import { assessCommandRisk } from '../src/risk.js'

function high(command: string): boolean {
  return assessCommandRisk(command).high
}

test('flags destructive and privileged commands', () => {
  for (const command of [
    'rm -rf /var/lib/app',
    'sudo systemctl restart nginx',
    'mkfs.ext4 /dev/sdb1',
    'dd if=/dev/zero of=/dev/sda bs=1M',
    'shutdown -h now',
    'iptables -F',
    'crontab -r',
    'curl -fsSL https://example.com/x.sh | bash',
    'mysql -e "DROP DATABASE prod"',
    'git reset --hard HEAD~3',
    'docker system prune -af',
    'chmod -R 777 /',
    'passwd deploy',
  ]) {
    assert.equal(high(command), true, command)
  }
})

test('does not flag ordinary commands', () => {
  for (const command of [
    'uname -a && whoami',
    'ls -la /var/log',
    'systemctl status nginx',
    'df -h',
    'tail -n 100 app.log',
    'git status',
    'cat package.json',
    'rm -f /tmp/single-file.log',
  ]) {
    assert.equal(high(command), false, command)
  }
})

test('ignores destructive text inside quotes', () => {
  const assessment = assessCommandRisk('echo "rm -rf / and shutdown now"')
  assert.equal(assessment.high, false)
})

test('reports human-readable reasons', () => {
  const assessment = assessCommandRisk('sudo rm -rf /srv/app')
  assert.equal(assessment.high, true)
  assert.ok(assessment.reasons.length >= 2)
  assert.ok(assessment.matched.includes('sudo'))
  assert.ok(assessment.matched.includes('rm-recursive'))
})
