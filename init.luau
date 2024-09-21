local jwt = require("package")

print(jwt.encode({
    user = "hi"
}, "jackshit", "hs256"))