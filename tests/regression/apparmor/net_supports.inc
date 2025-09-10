# Test parser_supports flag to test how parser is doing internal encoding
# the features file only gives the option of v7 socket mediation
# without finegrained af_unix or ip mediation.
# If the parser doesnt support v7, this forces a rule downgrade.
# which we can then error out on.
parser_supports_v7_socket_encode()
{
	local res=$(parser_supports --features-file=abis/socket_v7 --warn=rule-downgraded --Werror=rule-downgraded --warn=rule-not-enforced --Werror=rule-not-enforced -- "unix bind addr=@test,")
	[ "$res" == "true" ] && return 0
	return $?
}

parser_supports_ubuntu_socket()
{
	parser_supports_v7_socket_encode
	return $?
}

# Test parser_supports flag to test how parser is doing internal encoding
# the features file only gives the option of v8 socket mediation
# without finegrained af_unix or ip mediation.
# If the parser doesnt support v8, this forces a rule downgrade.
# which we can then error out on.
parser_supports_v8_socket_encode()
{
	local res=$(parser_supports --features-file=abis/socket_v8 --warn=rule-downgraded --Werror=rule-downgraded --warn=rule-not-enforced --Werror=rule-not-enforced -- "unix bind addr=@test,")
	[ "$res" == "true" ] && return 0
	return $?
}

# Test parser_supports flag to test how parser is doing internal encoding
# the features file only gives the option of v8 socket mediation
# without finegrained af_unix or ip mediation.
# If the parser doesnt support v8, this forces a rule downgrade.
# which we can then error out on.
parser_supports_v9_socket_encode()
{
	local res=$(parser_supports --features-file=abis/socket_v9 --warn=rule-downgraded --Werror=rule-downgraded --warn=rule-not-enforced --Werror=rule-not-enforced -- "unix bind addr=@test,")
	[ "$res" == "true" ] && return 0
	return $?
}

parser_supports_upstream_socket()
{
	parser_supports_v9_socket_encode || parser_supports_v8_socket_encode || return $?
	return 0
}

# Test parser_supports flag to test how parser is doing internal encoding
# the features file only gives the option of v7 or older v7 socket mediation
# without finegrained mediation.
# If the parser doesnt support v7, this forces a rule downgrade.
# which we can then error out on.
parser_supports_v7_unix_encode()
{
	local res=$(parser_supports --features-file=abis/af_unix_v7 --warn=rule-downgraded --Werror=rule-downgraded --warn=rule-not-enforced --Werror=rule-not-enforced -- "unix bind addr=@test,")
	[ "$res" == "true" ] && return 0
	return $?
}

# There is no v8 af_unix

# Test parser_supports flag to test how parser is doing internal encoding
# the features file only gives the option of v9 or older v7 socket mediation
# without finegrained mediation.
# If the parser doesnt support v9, this forces a rule downgrade.
# which we can then error out on.
parser_supports_v9_unix_encode()
{
	local res=$(parser_supports --features-file=abis/af_unix_v9 --warn=rule-downgraded --Werror=rule-downgraded --warn=rule-not-enforced --Werror=rule-not-enforced -- "unix bind addr=@test,")
	[ "$res" == "true" ] && return 0
	return $?
}

# TODO:
# - add tests for extened_v9_unix rules
# - add conditional and update current tests for semantic changes under
#   extended_v9_unix
#  this conditional can be used to enclose tests older parsers won't
#  be able to.
parser_supports_extended_v9_unix()
{
	# turn downgrade warning into error to make sure we catch downgrade
	# use a rule not supported by non-v9 parser to catch non-v9 parsers
	# which might not treat a unix rule as downgrade
	local res=$(parser_supports --features-file=abis/af_unix_v9 --warn=rule-downgraded --Werror=rule-downgraded --warn=rule-not-enforced --Werror=rule-not-enforced -- "unix rw addr=/path,")
	[ "$res" == "true" ] && return 0
	return $?
}

# Both kernel and parser support v7 af_unix rules
supports_unix_v7()
{
	local res=$(kernel_features network/af_unix)
	[ "$res" == "true" ]  && parser_supports_v7_unix_encode && return 0
	return $?
}

# Both kernel and parser support v9 af_unix rules
supports_unix_v9()
{
	local res=$(kernel_features network_v9/af_unix)
	[ "$res" == "true" ] && parser_supports_v9_unix_encode && return 0
	return $?
}

# Both kernel and parser support af_unix rules
supports_unix_rules()
{
	supports_unix_v9 || supports_unix_v7 || return $?
	return 0
}

supports_socket_v7()
{
	local res=$(kernel_features network/af_mask)
	[ "$res" == "true" ] && parser_supports_v7_socket_encode && return 0
	return $?
}

supports_socket_v8()
{
	local res=$(kernel_features network_v8/af_mask)
	[ "$res" == "true" ] && parser_supports_v8_socket_encode && return 0
	return $?
}

supports_socket_v9()
{
	local res=$(kernel_features network_v9/af_mask)
	[ "$res" == "true" ] && parser_supports_v9_socket_encode && return 0
	return $?
}

# Both kernel and parser support some combination of socket mediation
supports_socket_mediation()
{
	supports_socket_v9 || supports_socket_v8 || supports_socket_v7 || return $?
	return 0
}
