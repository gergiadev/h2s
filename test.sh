#!/bin/bash

# With "require-auth: true" in h2s.conf add the admin password as a bearer token:
# out=$(curl -H "Authorization: Bearer ${H2S_ADMIN_PASSWORD}" "http://localhost:23432/get?name=bb-web1-aec&pretty")
out=$(curl "http://localhost:23432/get?name=bb-web1-aec&pretty")
ifTable=($(echo $out | jq '.iftable1.ifName | .[]'))


echo "SYSTEM.Cpu.Idle,$(echo ${out} | jq -r '.default3 | ."ssCpuIdle.0"')"
echo "SYSTEM.Cpu.System,$(echo ${out} | jq -r '.default3 | ."ssCpuSystem.0"')"
echo "SYSTEM.Cpu.User,$(echo ${out} | jq -r '.default3 | ."ssCpuUser.0"')"

for i in "${!ifTable[@]}"
do
	echo "NETWORK.$(echo ${out} | jq -r ".iftable1.ifName[${i}]").inByte,$(echo ${out} | jq -r ".iftable1.ifHCInOctets[${i}]")"
	echo "NETWORK.$(echo ${out} | jq -r ".iftable1.ifName[${i}]").inPckt,$(echo ${out} | jq -r ".iftable1.ifHCInUcastPkts[${i}]")"
	echo "NETWORK.$(echo ${out} | jq -r ".iftable1.ifName[${i}]").outByte,$(echo ${out} | jq -r ".iftable1.ifHCOutOctets[${i}]")"
	echo "NETWORK.$(echo ${out} | jq -r ".iftable1.ifName[${i}]").outPckt,$(echo ${out} | jq -r ".iftable1.ifHCOutUcastPkts[${i}]")"
done
