#! /bin/bash
#	Copyright (C) 2019 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME nnp
#=DESCRIPTION
# Verifies AppArmor interactions with NO_NEW_PRIVS
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"

settest transition

file=$tmpdir/file
okperm=rw

fileok="${file}:${okperm}"

getcon="/proc/*/attr/current:r"
setcon="/proc/*/attr/current:w"
setexec="/proc/*/attr/exec:w"
policy="/sys/kernel/security/apparmor/"

touch $file

for iface in "" "-B" ; do
# Verify file access by an unconfined process
runchecktest "NNP iface='$iface' (unconfined - no NNP)" pass $iface -f "$file"
runchecktest "NNP iface='$iface' (unconfined - NNP)" pass $iface -n -f "$file"

# Verify file access under simple confinement
genprofile "$fileok" "$getcon"
runchecktest "NNP iface='$iface' (confined - no NNP)" pass $iface -f "$file"
runchecktest "NNP iface='$iface' (confined - NNP)" pass $iface -n -f "$file"

# Verify that NNP allows ix transitions
genprofile image="$test" "$fileok" "$getcon"
runchecktest "NNP iface='$iface' (ix - no NNP)" pass $iface -- "$test" -f "$file"
runchecktest "NNP iface='$iface' (ix - NNP)" pass $iface -- "$test" -n -f "$file"

# Verify that NNP causes unconfined profile transition failures
# NNP-induced failures will use EPERM rather than EACCES
genprofile -I "$test":rux "$fileok"
runchecktest "NNP iface='$iface' (ux - no NNP)" pass $iface -- "$test" -f "$file"
runchecktest_errno EPERM "NNP iface='$iface' (ux - NNP)" fail $iface -n -- "$test" -f "$file"

# Verify that NNP causes discrete profile transition failures
genprofile "$bin/open":px -- image="$bin/open" "$fileok"
runchecktest "NNP iface='$iface' (px - no NNP)" pass $iface -- "$bin/open" "$file"
runchecktest_errno EPERM "NNP iface='$iface' (px - NNP)" fail $iface -n -- "$bin/open" "$file"

# Verify that NNP causes change onexec failures
genprofile "change_profile->":"$bin/open" "$setexec" -- image="$bin/open" "$fileok"
runchecktest "NNP iface='$iface' (change onexec - no NNP)" pass $iface -O "$bin/open" -- "$bin/open" "$file"
runchecktest_errno EPERM "NNP iface='$iface' (change onexec - NNP)" fail $iface -n -O "$bin/open" -- "$bin/open" "$file"

# Verify that NNP causes change profile failures
genprofile "change_profile->":"$bin/open" "$setcon" -- image="$bin/open"
runchecktest "NNP iface='$iface' (change profile - no NNP)" pass $iface -P "$bin/open"
runchecktest_errno EPERM "NNP iface='$iface' (change profile - NNP)" fail $iface -n -P "$bin/open"

if [ "$(kernel_features_istrue domain/stack)" != "true" ] ; then
    echo "	kernel does not support profile stacking - skipping stacking nnp tests ..."
else

    # Verify that NNP allows stack onexec of another profile
    genprofile "$fileok" "$setexec" "change_profile->:&${bin}/open" -- image="$bin/open" "$fileok"
    runchecktest "NNP iface='$iface' (stack onexec - no NNP)" pass $iface -o "$bin/open" -- "$bin/open" "$file"
    runchecktest "NNP iface='$iface' (stack onexec - NNP)" pass $iface -n -o "$bin/open" -- "$bin/open" "$file"

    # Verify that NNP allows stacking another profile
    genprofile "$fileok" "$setcon" "change_profile->:&$bin/open" -- image="$bin/open" "$fileok"
    runchecktest "NNP iface='$iface' (stack profile - no NNP)" pass $iface -p "$bin/open" -f "$file"
    runchecktest "NNP iface='$iface' (stack profile - NNP)" pass $iface -n -p "$bin/open" -f "$file"

    #Verify that NNP allow stacking unconfined along current profile
    #this allows verifying that a stack with unconfined still gets the
    #unconfined exception applied. It also tests that dropping unconfined
    #from the stack is allowed. ie.
    # transition//&unconfined -> transition//&open
    # and
    # transition//&unconfined -> transition//&open//&unconfined
    genprofile "$fileok" "$setcon" "change_profile->:&$bin/open" "change_profile->:&unconfined" -- image="$bin/open" "$fileok"
    runchecktest "NNP iface='$iface' (stack profile&unconfined - no NNP)" pass $iface -i "&unconfined" -p "$bin/open" -f "$file"
    runchecktest "NNP iface='$iface' (stack profile&unconfined - NNP)" pass $iface -n -i "&unconfined" -p "$bin/open" -f "$file"

    genprofile "$fileok" "$setcon" "change_profile->:$bin/transition" "change_profile->:$bin/open" "change_profile->:&unconfined" -- image="$bin/open" "$fileok"
    runchecktest "NNP iface='$iface' (change profile&unconfined - no NNP)" pass $iface -i "&unconfined" -P "$bin/transition//&$bin/open" -f "$file"
    runchecktest "NNP iface='$iface' (change profile&unconfined - NNP)" pass $iface -n -i "&unconfined" -P "$bin/transition//&$bin/open" -f "$file"


    #Verify that NNP allows stacking a new policy namespace
    #must use stdin with genprofile for namespaces
    genprofile image=$test --stdin <<EOF
$test {
    @{gen_bin $test}
    @{gen_def}
    ${file} ${okperm},
    /proc/*/attr/current w,
    change_profile-> &:nnp:unconfined,
}
EOF
    genprofile --append image=:nnp:$bin/open --stdin <<EOF
:nnp:$bin/open {
    @{gen_bin $bin/open}
    @{gen_def}
    ${file} ${okperm},
}
EOF
    #genprofile is creating child namespace so mkdir not needed
    runchecktest "NNP iface='$iface' (stack :nnp:unconfined - no NNP)" pass $iface -p ":nnp:unconfined" -f "$file"
    runchecktest "NNP iface='$iface' (stack :nnp:unconfined - NNP)" pass $iface -n -p ":nnp:unconfined" -f "$file"

    runchecktest "NNP iface='$iface' (stack :nnp:open - no NNP)" fail $iface -p ":nnp:$bin/open" -f "$file"
    runchecktest "NNP iface='$iface' (stack :nnp:open - NNP)" fail $iface -n -p ":nnp:$bin/open" -f "$file"

    genprofile image=$test --stdin <<EOF
$test {
    @{gen_bin $test}
    @{gen_def}
    ${file} ${okperm},
    /proc/*/attr/current w,
    change_profile-> &:nnp:$bin/open,
}
EOF
    genprofile --append image=:nnp:$bin/open --stdin <<EOF
:nnp:$bin/open {
    @{gen_bin $bin/open}
    @{gen_def}
    ${file} ${okperm},
}
EOF
     runchecktest "NNP iface='$iface' (stack :nnp:open - no NNP)" pass $iface -p ":nnp:$bin/open" -f "$file"
    runchecktest "NNP iface='$iface' (stack :nnp:open - NNP)" pass $iface -n -p ":nnp:$bin/open" -f "$file"
    # explicitly remove profile before cleaning up the namespace so
    # prologue.inc auto cleanup doesn't fail
    removeprofile
    echo -n  ":nnp:" > "$policy/.remove" || echo "   warning failed to remove namespace policy/namespaces/nnp"

fi
done # for iface
