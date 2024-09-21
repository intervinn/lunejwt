local serde = require("@lune/serde")
local base64 = require("@extern/base64")

export type HashAlgorithm = "sha256" | "sha384" | "sha512"
export type HMACSign = "hs256" | "hs384" | "hs512"

local algPairs : {[HMACSign]: HashAlgorithm} = {
    ["hs256"] = "sha256",
    ["hs384"] = "sha384",
    ["hs512"] = "sha512"
}

local function b64url(str: string): string
    return str:gsub("=", ""):gsub("+", "-"):gsub("/", "-")
end

type Impl = {
    __index: Impl,
    encode: <T>(value: T, secret: string, algorithm: HMACSign) -> string,
}

type Proto = {

}

export type Header = {
    alg: string,
    typ: string?,
    cty: string?
}

export type Payload = {
    iss: string?,
    sub: string?,
    aud: string?,
    exp: string?,
    nbf: string?,
    iat: string?,
    jti: string?
} & {[string]: any}

local JWT: Impl = {} :: Impl
JWT.__index = JWT
export type JWT = typeof(setmetatable({} :: Proto, {} :: Impl))

function JWT.encode<T>(value: T, secret: string, algorithm: HMACSign)
    local payload = value
    local header: Header = {
        alg = algorithm,
        typ = "JWT"
    }
    
    local payloadb64 = b64url(buffer.tostring(base64.encode(buffer.fromstring(serde.encode("json", payload ,false)))))
    local headerb64 = b64url(buffer.tostring(base64.encode(buffer.fromstring(serde.encode("json", header, false)))))

    local signature = serde.hmac(
        algPairs[algorithm],
        headerb64.."."..payloadb64,
        secret
    )

    return headerb64.."."..payloadb64.."."..signature
end

return JWT