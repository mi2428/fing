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
puts 'CI contract OK'
