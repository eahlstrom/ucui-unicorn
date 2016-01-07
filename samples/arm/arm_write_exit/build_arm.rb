#!/usr/bin/env ruby
require 'pp'

as = %{/usr/bin/arm-none-eabi-as}
objdump = %{/usr/bin/arm-none-eabi-objdump}
name = ARGV[0] || "arm_write_exit"

if !File.exist?(as) || !File.exist?(objdump)
  puts "Cannot find required arm binaries!"
  puts "on ubuntu they are located in package \"binutils-arm-none-eabi\""
  exit 1
end

if !File.exist?(name + ".s")
  puts "Usage: #{File.basename($0)} name"
  puts " builds a file named name.s"
  exit 1
end

cmd = %{#{as} -o #{name} #{name}.s}
puts cmd
exit 2 unless system(cmd)

cmd = %{#{objdump} -d #{name}}
puts cmd
out = `#{cmd}`
format = out.scan(/file format (\S+)/).flatten.first || raise("no file format found")

opcodes = []
case format
when 'elf32-littlearm'
  rbytes = out.scan(/^\s+[0-9a-f]+:\s+(\S+)/).collect do |b|
    b[0].scan(/\w\w/).reverse.collect{|sn| sn.to_i(16)}
  end
  ;;
else
  puts "format: #{format} unknown"
  exit 1
end
rbytes = rbytes.flatten

scfile = name + ".sc"
File.open(scfile, "w") do |fh|
  fh.print rbytes.pack("C*")
end

puts "Generated file: #{scfile}"
puts "Run with: ucui -a ARM #{scfile}"
