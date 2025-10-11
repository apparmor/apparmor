#! /bin/bash
#	Copyright (C) 2025 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME allow_all
#=DESCRIPTION
# Verifies that allow all profiles work as expected and use implicit pix transitions
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"

# Two profiles are needed here:
# 1. Load a custom profile-with-attachment for ${bin}/allow_all
# 2. Load an allow_all profile for ${bin}/complain
# 3. Execute ${bin}/complain under the allow_all profile and check the confinement that ${bin}/allow_all fell under

cat <<EOF > ${tmpdir}/allow_all_profile
abi <kernel>,

profile regression_allow_all ${bin}/getcon_verify {
allow all,
}
EOF

"${subdomain}" ${parser_args} ${tmpdir}/allow_all_profile

settest allow_all "${bin}/complain"

genprofile "allow all"
runchecktest "Allow all - ix default" pass exec "${bin}/getcon_verify" "${bin}/complain" "enforce"
genprofile "allow all" "/**:pix"
runchecktest "Allow all - pix rule" pass exec "${bin}/getcon_verify" "regression_allow_all" "enforce"

"${subdomain}" ${parser_args} -R ${tmpdir}/allow_all_profile
