require 'yaml'

Dir.chdir(File.expand_path('../..', __dir__))
workflow = YAML.load_file('.github/workflows/quality.yml')
raise 'missing PR checks' unless workflow.fetch('on').key?('pull_request')
raise 'missing branch checks' unless workflow.fetch('on').fetch('push').fetch('branches').sort == %w[develop main]
raise 'excess permissions' unless workflow.fetch('permissions') == { 'contents' => 'read' }
job = workflow.fetch('jobs').fetch('check')
raise 'missing OS checks' unless job.fetch('strategy').fetch('matrix').fetch('os').sort == %w[macos-15 ubuntu-24.04]
raise 'wrong runner' unless job.fetch('runs-on') == '${{ matrix.os }}'
steps = job.fetch('steps')
raise 'persisted credentials' unless steps.first.fetch('with').fetch('persist-credentials') == false
raise 'wrong quality gates' unless steps.drop(1).map { |step| step.fetch('run') } == [
  'rustup toolchain install --no-self-update', 'ruby .github/tests/ci_contract.rb', 'make check'
]
raise 'checks can be skipped' if ([job] + steps).any? { |entry| entry.key?('if') || entry.key?('continue-on-error') }
makefile = File.read('Makefile')
%w[lint doc test].each do |target|
  recipe = makefile.match(/^#{target}:.*\n(\t[^\n]*\n)+/).to_s
  raise "#{target} must use locked resolution" unless recipe.include?('--locked')
end
advisory = YAML.load_file('.github/workflows/advisories.yml')
raise 'missing advisory PR checks' unless advisory.fetch('on').key?('pull_request')
raise 'missing advisory schedule' unless advisory.fetch('on').fetch('schedule').any?
raise 'excess advisory permissions' unless advisory.fetch('permissions') == { 'contents' => 'read' }
audit_job = advisory.fetch('jobs').fetch('audit')
raise 'Docker check requires Linux' unless audit_job.fetch('runs-on') == 'ubuntu-24.04'
audit_steps = audit_job.fetch('steps')
raise 'persisted advisory credentials' unless audit_steps.first.fetch('with').fetch('persist-credentials') == false
scan = audit_steps.last
raise 'incomplete lockfile check' unless scan.fetch('run').split == [
  'docker', 'run', '--rm', '--volume', '"$PWD:/src:ro"',
  'ghcr.io/google/osv-scanner@sha256:afd838850ac1a0fcc15ff4a041dc9ba11123c3f0d2666217a5f0fcf9222b55fa',
  'scan', 'source', '--lockfile=/src/Cargo.lock'
]
raise 'advisories can be skipped' if ([audit_job] + audit_steps).any? { |entry| entry.key?('if') || entry.key?('continue-on-error') }
updates = YAML.load_file('.github/dependabot.yml')
raise 'wrong update config version' unless updates.fetch('version') == 2
cargo = updates.fetch('updates').fetch(0)
raise 'wrong update ecosystem' unless cargo.fetch('package-ecosystem') == 'cargo' && cargo.fetch('directory') == '/'
raise 'wrong update interval' unless cargo.fetch('schedule').fetch('interval') == 'weekly'
raise 'excess update PRs' unless cargo.fetch('open-pull-requests-limit') == 5
raise 'updates must be individually reviewable' if cargo.key?('groups') || cargo.key?('ignore')
puts 'CI contract OK'
