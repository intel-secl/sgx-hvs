#!/bin/bash

op=$1

if [ -z $op ]; then
	echo "No operation provided"
	op="reg"
fi

v_host_name="skchost-sgx-agent"
v_connection_string="http://127.0.0.1:5000/hosts"
v_description="host information"
v_uuid="42194838-4966-8b1b-f521-0f84c977e3ad"
v_host_id="f2634d27-5fae-4982-89a5-d3aa4879a2ed"
v_id="4fbce0de-fd41-48d5-886c-ca5ebd6f820e"
#v_host_status="Updated"
v_latestper_host="true"
v_host_state="true"

shvs_host="127.0.0.1"
shvs_port=13000

out_file=.out.log

echo "$no_proxy" | grep "$shvs_host"
if [ $? -ne 0 ]; then
	if [ -z $op ]; then
		export no_proxy="$shvs_host"
	else
		export no_proxy=$no_proxy",$shvs_host"
	fi
fi

if [ "$op" = "reg" ]; then
	rh_create_json_file=./.register_host_create.json
printf "{
\"host_name\": \"$v_host_name\",
\"connection_string\": \"$v_connection_string\",
\"description\": \"$v_description\",
\"uuid\": \"$v_uuid\"
}" > $rh_create_json_file

	curl -X POST -vvv --tlsv1.2  "https://$shvs_host:$shvs_port/sgx-hvs/v1/hosts" -H "Content-Type: application/json" --data @$rh_create_json_file -s --insecure > $out_file
	cat $out_file

elif [ "$op" = "re-reg" ]; then

	rh_create_json_file=./.re-register_host_create.json
printf "{
\"host_name\": \"$v_host_name\",
\"connection_string\": \"$v_connection_string\",
\"description\": \"$v_description\",
\"uuid\": \"$v_uuid\",
\"overwrite\": true
}" > $rh_create_json_file

	curl -X POST -vvv --tlsv1.2  "https://$shvs_host:$shvs_port/sgx-hvs/v1/hosts" -H "Content-Type: application/json" --data @$rh_create_json_file -s --insecure

elif [ "$op" = "de-reg" ]; then

	if dnf list installed "jq" >/dev/null 2>&1; then
        	echo "package already installed"
	else
		dnf install jq -y
	fi

	id=`jq '.Id' $out_file | sed 's/"//g'`
	echo "De register Host: $id"
	curl -X DELETE -vvv --tlsv1.2  "https://$shvs_host:$shvs_port/sgx-hvs/v1/hosts/$id" -s --insecure

elif [ "$op" = "report" ]; then

        curl -X GET -vvv --tlsv1.2  "https://$shvs_host:$shvs_port/sgx-hvs/v1/reports?hostName=$v_host_name&hostHardwareId=$v_uuid&id=$v_id&hostId=$v_host_id&hostStatus=$v_host_status" -s --insecure

elif [ "$op" = "latestperhost" ]; then

        curl -X GET -vvv --tlsv1.2  "https://$shvs_host:$shvs_port/sgx-hvs/v1/reports?latestPerHost=$v_latestper_host" -s --insecure

elif [ "$op" = "host-status" ]; then

	curl -X GET -vvv --tlsv1.2  "https://$shvs_host:$shvs_port/sgx-hvs/v1/host-status?latestPerHost=$v_host_state" -s --insecure
else
	echo "No valid operations supplied"
fi
