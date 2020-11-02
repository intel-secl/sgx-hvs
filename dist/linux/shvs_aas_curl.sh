#!/bin/bash

echo "Setting up SGX Host Verification ServiceRelated roles and user in AAS Database"

source ~/shvs.env 2> /dev/null

#Get the value of AAS IP address and port. Default vlue is also provided.
aas_hostname=${AAS_API_URL:-"https://<aas.server.com>:8444/aas"}
CURL_OPTS="-s -k"
CONTENT_TYPE="Content-Type: application/json"
ACCEPT="Accept: application/jwt"
CN="SHVS TLS Certificate"

red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`

mkdir -p /tmp/setup/shvs
tmpdir=$(mktemp -d -p /tmp/setup/shvs)

cat >$tmpdir/aasAdmin.json <<EOF
{
	"username": "admin@aas",
	"password": "aasAdminPass"
}
EOF

#Get the AAS Admin JWT Token
curl_output=`curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "$ACCEPT" --data @$tmpdir/aasAdmin.json -w "%{http_code}" $aas_hostname/token`
Bearer_token=`echo $curl_output | rev | cut -c 4- | rev`

dnf install -qy jq

# This routined checks if shvs user exists and reurns user id
# it creates a new user if one does not exist
create_shvs_user()
{
cat > $tmpdir/user.json << EOF
{
	"username":"$SHVS_ADMIN_USERNAME",
	"password":"$SHVS_ADMIN_PASSWORD"
}
EOF

	#check if user already exists
	curl $CURL_OPTS -H "Authorization: Bearer ${Bearer_token}" -o $tmpdir/user_response.json -w "%{http_code}" $aas_hostname/users?name=$SHVS_ADMIN_USERNAME > $tmpdir/user-response.status

	len=$(jq '. | length' < $tmpdir/user_response.json)
	if [ $len -ne 0 ]; then
		user_id=$(jq -r '.[0] .user_id' < $tmpdir/user_response.json)
	else
		curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/user.json -o $tmpdir/user_response.json -w "%{http_code}" $aas_hostname/users > $tmpdir/user_response.status

		local status=$(cat $tmpdir/user_response.status)
		if [ $status -ne 201 ]; then
			return 1
		fi

		if [ -s $tmpdir/user_response.json ]; then
			user_id=$(jq -r '.user_id' < $tmpdir/user_response.json)
			if [ -n "$user_id" ]; then
				echo "${green} Created shvs user, id: $user_id ${reset}"
			fi
		fi
	fi
}

# This routined checks if shvs CertApprover/CacheManager roles exist and reurns those role ids
# it creates above roles if not present in AAS db
create_roles()
{
cat > $tmpdir/certroles.json << EOF
{
	"service": "CMS",
	"name": "CertApprover",
	"context": "CN=$CN;SAN=$SAN_LIST;CERTTYPE=TLS"
}
EOF

cat > $tmpdir/hostlistmanagerroles.json << EOF
{
	"service": "SHVS",
	"name": "HostListManager",
	"context": ""
}
EOF

cat > $tmpdir/hostslistreaderroles.json << EOF
{
	"service": "SHVS",
	"name": "HostsListReader",
	"context": ""
}
EOF

cat > $tmpdir/shvshostdatareaderroles.json << EOF
{
	"service": "SHVS",
	"name": "HostDataReader",
	"context": ""
}
EOF

cat > $tmpdir/scshostdatareaderroles.json << EOF
{
	"service": "SCS",
	"name": "HostDataReader",
	"context": ""
}
EOF

cat > $tmpdir/agenthostdatareaderroles.json << EOF
{
	"service": "SGX_AGENT",
	"name": "HostDataReader",
	"context": ""
}
EOF

cat > $tmpdir/shvshostdataupdaterroles.json << EOF
{
	"service": "SCS",
	"name": "HostDataUpdater",
	"context": ""
}
EOF

	#check if CertApprover role already exists
	curl $CURL_OPTS -H "Authorization: Bearer ${Bearer_token}" -o $tmpdir/role_response.json -w "%{http_code}" $aas_hostname/roles?name=CertApprover > $tmpdir/role_response.status

	cms_role_id=$(jq --arg SAN $SAN_LIST -r '.[] | select ( .context | ( contains("SHVS") and contains($SAN)))' < $tmpdir/role_response.json | jq -r '.role_id')
	if [ -z $cms_role_id ]; then
		curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/certroles.json -o $tmpdir/role_response.json -w "%{http_code}" $aas_hostname/roles > $tmpdir/role_response-status.json

		local status=$(cat $tmpdir/role_response-status.json)
		if [ $status -ne 201 ]; then
			return 1
		fi

		if [ -s $tmpdir/role_response.json ]; then
			cms_role_id=$(jq -r '.role_id' < $tmpdir/role_response.json)
		fi
	fi

	#check if SHVS HostListManager role already exists
	curl $CURL_OPTS -H "Authorization: Bearer ${Bearer_token}" -o $tmpdir/role_resp.json -w "%{http_code}" $aas_hostname/roles?name=HostListManager > $tmpdir/role_resp.status
	len=$(jq '. | length' < $tmpdir/role_resp.json)
	if [ $len -ne 0 ]; then
		shvs_role_id1=$(jq -r '.[0] .role_id' < $tmpdir/role_resp.json)
	else
		curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/hostlistmanagerroles.json -o $tmpdir/role_resp.json -w "%{http_code}" $aas_hostname/roles > $tmpdir/role_resp-status.json

		local status=$(cat $tmpdir/role_resp-status.json)
		if [ $status -ne 201 ]; then
			return 1
		fi

		if [ -s $tmpdir/role_resp.json ]; then
			shvs_role_id1=$(jq -r '.role_id' < $tmpdir/role_resp.json)
		fi
	fi
	#check if SHVS HostsListReader role already exists
	curl $CURL_OPTS -H "Authorization: Bearer ${Bearer_token}" -o $tmpdir/role_resp.json -w "%{http_code}" $aas_hostname/roles?name=HostsListReader > $tmpdir/role_resp.status
	len=$(jq '. | length' < $tmpdir/role_resp.json)
	if [ $len -ne 0 ]; then
		shvs_role_id2=$(jq -r '.[0] .role_id' < $tmpdir/role_resp.json)
	else
		curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/hostslistreaderroles.json -o $tmpdir/role_resp.json -w "%{http_code}" $aas_hostname/roles > $tmpdir/role_resp-status.json

		local status=$(cat $tmpdir/role_resp-status.json)
		if [ $status -ne 201 ]; then
			return 1
		fi

		if [ -s $tmpdir/role_resp.json ]; then
			shvs_role_id2=$(jq -r '.role_id' < $tmpdir/role_resp.json)
		fi
	fi
	#check if SHVS HostDataUpdater role already exists
	curl $CURL_OPTS -H "Authorization: Bearer ${Bearer_token}" -o $tmpdir/role_resp.json -w "%{http_code}" $aas_hostname/roles?name=HostDataReader > $tmpdir/role_resp.status
	shvs_role_id3=$(jq -r '.[] | select ( .service | contains("SHVS"))' < $tmpdir/role_resp.json | jq -r '.role_id')
	scs_role_id1=$(jq -r '.[] | select ( .service | contains("SCS"))' < $tmpdir/role_resp.json | jq -r '.role_id')
	agent_role_id=$(jq -r '.[] | select ( .service | contains("SGX_AGENT"))' < $tmpdir/role_resp.json | jq -r '.role_id')
	if [ -z $shvs_role_id3 ]; then
		curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/shvshostdatareaderroles.json -o $tmpdir/role_resp.json -w "%{http_code}" $aas_hostname/roles > $tmpdir/role_resp-status.json

		local status=$(cat $tmpdir/role_resp-status.json)
		if [ $status -ne 201 ]; then
			return 1
		fi

		if [ -s $tmpdir/role_resp.json ]; then
			shvs_role_id3=$(jq -r '.role_id' < $tmpdir/role_resp.json)
		fi

	fi
	if [ -z $scs_role_id1 ]; then
		curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/scshostdatareaderroles.json -o $tmpdir/role_resp.json -w "%{http_code}" $aas_hostname/roles > $tmpdir/role_resp-status.json

		local status=$(cat $tmpdir/role_resp-status.json)
		if [ $status -ne 201 ]; then
			return 1
		fi

		if [ -s $tmpdir/role_resp.json ]; then
			scs_role_id1=$(jq -r '.role_id' < $tmpdir/role_resp.json)
		fi

	fi
	if [ -z $agent_role_id ]; then
		curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/agenthostdatareaderroles.json -o $tmpdir/role_resp.json -w "%{http_code}" $aas_hostname/roles > $tmpdir/role_resp-status.json

		local status=$(cat $tmpdir/role_resp-status.json)
		if [ $status -ne 201 ]; then
			return 1
		fi

		if [ -s $tmpdir/role_resp.json ]; then
			agent_role_id=$(jq -r '.role_id' < $tmpdir/role_resp.json)
		fi
	fi

	curl $CURL_OPTS -H "Authorization: Bearer ${Bearer_token}" -o $tmpdir/role_resp.json -w "%{http_code}" $aas_hostname/roles?name=HostDataUpdater > $tmpdir/role_resp.status
	len=$(jq '. | length' < $tmpdir/role_resp.json)
	if [ $len -ne 0 ]; then
		scs_role_id2=$(jq -r '.[0] .role_id' < $tmpdir/role_resp.json)
	else
		curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/shvshostdataupdaterroles.json -o $tmpdir/role_resp.json -w "%{http_code}" $aas_hostname/roles > $tmpdir/role_resp-status.json

		local status=$(cat $tmpdir/role_resp-status.json)
		if [ $status -ne 201 ]; then
			return 1
		fi

		if [ -s $tmpdir/role_resp.json ]; then
			scs_role_id2=$(jq -r '.role_id' < $tmpdir/role_resp.json)
		fi
	fi

	ROLE_ID_TO_MAP=`echo \"$cms_role_id\",\"$shvs_role_id1\",\"$shvs_role_id2\",\"$shvs_role_id3\",\"$scs_role_id1\",\"$scs_role_id2\",\"$agent_role_id\"`
}

#Maps scs user to CertApprover/CacheManager Roles
mapUser_to_role()
{
cat >$tmpdir/mapRoles.json <<EOF
{
	"role_ids": [$ROLE_ID_TO_MAP]
}
EOF

	curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/mapRoles.json -o $tmpdir/mapRoles_response.json -w "%{http_code}" $aas_hostname/users/$user_id/roles > $tmpdir/mapRoles_response-status.json

	local status=$(cat $tmpdir/mapRoles_response-status.json)
	if [ $status -ne 201 ]; then
		return 1
	fi
}

SHVS_SETUP_API="create_shvs_user create_roles mapUser_to_role"
status=
for api in $SHVS_SETUP_API
do
	eval $api
    	status=$?
	if [ $status -ne 0 ]; then
		break;
	fi
done

if [ $status -ne 0 ]; then
	echo "${red} SGX Host Verification Service user/roles creation failed.: $api ${reset}"
	exit 1
else
	echo "${green} SGX Host Verification Service user/roles creation succeded ${reset}"
fi

#Get Token for SHVS user and configure it in shvs config.
curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "$ACCEPT" --data @$tmpdir/user.json -o $tmpdir/shvs_token-resp.json -w "%{http_code}" $aas_hostname/token > $tmpdir/get_shvs_token-response.status

status=$(cat $tmpdir/get_shvs_token-response.status)
if [ $status -ne 200 ]; then
	echo "${red} Couldn't get bearer token for shvs user ${reset}"
else
	export BEARER_TOKEN=`cat $tmpdir/shvs_token-resp.json`
	echo "************************************************************************************************************************************************"
	echo $BEARER_TOKEN
	echo "************************************************************************************************************************************************"
	echo "${green} copy the above token and paste it against BEARER_TOKEN in shvs.env ${reset}"
fi

# cleanup
rm -rf $tmpdir
