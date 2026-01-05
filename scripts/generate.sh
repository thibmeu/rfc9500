#!/usr/bin/env bash

########
# PEMs #
########

# Generate public keys
for n in {1024,2048,4096}; do openssl dsa -in "./pem/testDLP${n}.pem" -pubout -out "./pem/testDLP${n}.pub.pem";  done
for n in {256,384,521}; do openssl ec -in "./pem/testECCP${n}.pem" -pubout -out "./pem/testECCP${n}.pub.pem";  done
for n in {1024,2048,4096}; do openssl rsa -in "./pem/testRSA${n}.pem" -pubout -out "./pem/testRSA${n}.pub.pem";  done


########
# HEXs #
########

mkdir -p hex

# Private keys in hex
openssl dsa -in ./pem/testDLP1024.pem -text -noout 2>/dev/null | grep "priv:" -A 2 | tail -n +2 | tr -d ' \n:' > ./hex/testDLP1024.hex
openssl dsa -in ./pem/testDLP2048.pem -text -noout 2>/dev/null | grep "priv:" -A 2 | tail -n +2 | tr -d ' \n:' > ./hex/testDLP2048.hex
openssl dsa -in ./pem/testDLP4096.pem -text -noout 2>/dev/null | grep "priv:" -A 3 | tail -n +2 | tr -d ' \n:' > ./hex/testDLP4096.hex
openssl ec -in ./pem/testECCP256.pem -text -noout 2>/dev/null | grep "priv:" -A 3 | tail -n +2 | tr -d ' \n:' > ./hex/testECCP256.hex
openssl ec -in ./pem/testECCP384.pem -text -noout 2>/dev/null | grep "priv:" -A 4 | tail -n +2 | tr -d ' \n:' > ./hex/testECCP384.hex
openssl ec -in ./pem/testECCP521.pem -text -noout 2>/dev/null | grep "priv:" -A 5 | tail -n +2 | tr -d ' \n:' > ./hex/testECCP521.hex

# Public keys in hex
openssl dsa -in ./pem/testDLP1024.pem -text -noout 2>/dev/null | grep "pub:" -A 9 | tail -n +2 | tr -d ' \n:' > ./hex/testDLP1024.pub.hex
openssl dsa -in ./pem/testDLP2048.pem -text -noout 2>/dev/null | grep "pub:" -A 18 | tail -n +2 | tr -d ' \n:' > ./hex/testDLP2048.pub.hex
openssl dsa -in ./pem/testDLP4096.pem -text -noout 2>/dev/null | grep "pub:" -A 35 | tail -n +2 | tr -d ' \n:' > ./hex/testDLP4096.pub.hex
openssl ec -in ./pem/testECCP256.pem -text -noout 2>/dev/null | grep "pub:" -A 5 | tail -n +2 | tr -d ' \n:' > ./hex/testECCP256.pub.hex
openssl ec -in ./pem/testECCP384.pem -text -noout 2>/dev/null | grep "pub:" -A 7 | tail -n +2 | tr -d ' \n:' > ./hex/testECCP384.pub.hex
openssl ec -in ./pem/testECCP521.pem -text -noout 2>/dev/null | grep "pub:" -A 9 | tail -n +2 | tr -d ' \n:' > ./hex/testECCP521.pub.hex


########
# JWKs #
########

mkdir -p jwk

b64url() {
    echo "$1" | xxd -r -p | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
}

extract_hex() {
    local cmd=$1 file=$2 field=$3
    openssl "$cmd" -in "$file" -text -noout 2>/dev/null | sed -n "/$field:/,/^[^ ]/p" | grep -v ":" | tr -d ' \n'
}

generate_jwk() {
    local type=$1 size=$2 name=$3
    local pem_in="./pem/${name}.pem"
    local hex_in="./hex/${name}.hex"
    local hex_pub_in="./hex/${name}.pub.hex"

    case "$type" in
        rsa)
            local n
            n=$(openssl rsa -in "$pem_in" -noout -modulus | cut -d'=' -f2)
            local e
            e=$(openssl rsa -in "$pem_in" -noout -text | grep "publicExponent" | sed -E 's/.*\(0x([0-9a-fA-F]+)\).*/\1/')
            [[ $(( ${#e} % 2 )) -ne 0 ]] && e="0$e"

            local d
            d=$(extract_hex rsa "$pem_in" "privateExponent")
            local p
            p=$(extract_hex rsa "$pem_in" "prime1")
            local q
            q=$(extract_hex rsa "$pem_in" "prime2")
            local dp
            dp=$(extract_hex rsa "$pem_in" "exponent1")
            local dq
            dq=$(extract_hex rsa "$pem_in" "exponent2")
            local qi
            qi=$(extract_hex rsa "$pem_in" "coefficient")

            echo "{\"kid\":\"${name}\",\"kty\":\"RSA\",\"n\":\"$(b64url "$n")\",\"e\":\"$(b64url "$e")\"}" > "./jwk/${name}.pub.json"
            echo "{\"kid\":\"${name}\",\"kty\":\"RSA\",\"n\":\"$(b64url "$n")\",\"e\":\"$(b64url "$e")\",\"d\":\"$(b64url "$d")\",\"p\":\"$(b64url "$p")\",\"q\":\"$(b64url "$q")\",\"dp\":\"$(b64url "$dp")\",\"dq\":\"$(b64url "$dq")\",\"qi\":\"$(b64url "$qi")\"}" > "./jwk/${name}.json"
            ;;
        ec)
            local pub_hex
            pub_hex=$(cat "${hex_pub_in}")
            local coord_hex=${pub_hex#04}
            local len=$((${#coord_hex} / 2))
            local x=${coord_hex:0:$len}
            local y=${coord_hex:$len}

            local d
            d=$(cat "${hex_in}")

            echo "{\"kid\":\"${name}\",\"kty\":\"EC\",\"crv\":\"P-$size\",\"x\":\"$(b64url "$x")\",\"y\":\"$(b64url "$y")\"}" > "./jwk/${name}.pub.json"
            echo "{\"kid\":\"${name}\",\"kty\":\"EC\",\"crv\":\"P-$size\",\"x\":\"$(b64url "$x")\",\"y\":\"$(b64url "$y")\",\"d\":\"$(b64url "$d")\"}" > "./jwk/${name}.json"
            ;;
    esac
}

for n in {256,384,521}; do generate_jwk ec "${n}" "testECCP${n}";  done
for n in {1024,2048,4096}; do generate_jwk rsa "${n}" "testRSA${n}";  done