const crypto = require("crypto");

const TELEGRAM_CLIENT_ID =
    process.env.TELEGRAM_CLIENT_ID;

const TELEGRAM_CLIENT_SECRET =
    process.env.TELEGRAM_CLIENT_SECRET;

const TELEGRAM_BOT_TOKEN =
    process.env.TELEGRAM_BOT_TOKEN;

const TELEGRAM_CHANNEL =
    process.env.TELEGRAM_CHANNEL ||
    "@allaboutxlilnyx";

const OWNER_ID =
    "6282298313";


function base64url(buffer){

    return Buffer
        .from(buffer)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");

}


function randomString(){

    return base64url(
        crypto.randomBytes(32)
    );

}


function sha256Base64url(value){

    return base64url(
        crypto
            .createHash("sha256")
            .update(value)
            .digest()
    );

}


function parseCookies(req){

    const header =
        req.headers.cookie || "";

    const cookies = {};

    header
        .split(";")
        .forEach(part => {

            const index =
                part.indexOf("=");

            if(index === -1)
                return;

            const key =
                part
                    .slice(0,index)
                    .trim();

            const value =
                part
                    .slice(index + 1)
                    .trim();

            cookies[key] =
                decodeURIComponent(value);

        });

    return cookies;

}


function signSession(payload){

    const encoded =
        base64url(
            Buffer.from(
                JSON.stringify(payload)
            )
        );

    const signature =
        crypto
            .createHmac(
                "sha256",
                TELEGRAM_BOT_TOKEN
            )
            .update(encoded)
            .digest("hex");

    return encoded + "." + signature;

}


function verifySession(token){

    if(!token)
        return null;

    const parts =
        token.split(".");

    if(parts.length !== 2)
        return null;

    const encoded =
        parts[0];

    const signature =
        parts[1];

    const expected =
        crypto
            .createHmac(
                "sha256",
                TELEGRAM_BOT_TOKEN
            )
            .update(encoded)
            .digest("hex");

    if(
        signature.length !==
        expected.length
    ){

        return null;

    }

    if(
        !crypto.timingSafeEqual(
            Buffer.from(signature),
            Buffer.from(expected)
        )
    ){

        return null;

    }

    try{

        const payload =
            JSON.parse(
                Buffer
                    .from(
                        encoded,
                        "base64url"
                    )
                    .toString()
            );

        if(
            !payload.exp ||
            Date.now() >= payload.exp
        ){

            return null;

        }

        return payload;

    }catch{

        return null;

    }

}


function setCookie(
    res,
    name,
    value,
    options = {}
){

    let cookie =
        `${name}=${encodeURIComponent(value)}`;

    cookie +=
        "; Path=/";

    if(options.maxAge !== undefined){

        cookie +=
            `; Max-Age=${options.maxAge}`;

    }

    if(options.httpOnly !== false){

        cookie +=
            "; HttpOnly";

    }

    cookie +=
        "; SameSite=Lax";

    if(
        process.env.VERCEL ||
        process.env.NODE_ENV === "production"
    ){

        cookie +=
            "; Secure";

    }

    res.setHeader(
        "Set-Cookie",
        cookie
    );

}


async function getTelegramKeys(){

    const response =
        await fetch(
            "https://oauth.telegram.org/.well-known/jwks.json"
        );

    if(!response.ok){

        throw new Error(
            "Tidak dapat mengambil JWKS Telegram."
        );

    }

    return response.json();

}


function findJwk(
    keys,
    kid
){

    return (
        keys.keys || []
    ).find(
        key => key.kid === kid
    );

}


function decodeJwtPart(
    value
){

    return JSON.parse(
        Buffer
            .from(
                value,
                "base64url"
            )
            .toString()
    );

}


async function verifyTelegramIdToken(
    idToken
){

    const parts =
        idToken.split(".");

    if(parts.length !== 3){

        throw new Error(
            "Format ID token tidak valid."
        );

    }

    const header =
        decodeJwtPart(parts[0]);

    const payload =
        decodeJwtPart(parts[1]);

    if(
        header.alg !== "RS256"
    ){

        throw new Error(
            "Algoritma token tidak didukung."
        );

    }

    if(
        payload.iss !==
        "https://oauth.telegram.org"
    ){

        throw new Error(
            "Issuer token tidak valid."
        );

    }

    if(
        String(payload.aud) !==
        String(TELEGRAM_CLIENT_ID)
    ){

        throw new Error(
            "Audience token tidak valid."
        );

    }

    const now =
        Math.floor(
            Date.now() / 1000
        );

    if(
        !payload.exp ||
        payload.exp <= now
    ){

        throw new Error(
            "Token Telegram sudah kedaluwarsa."
        );

    }

    const keys =
        await getTelegramKeys();

    const jwk =
        findJwk(
            keys,
            header.kid
        );

    if(!jwk){

        throw new Error(
            "Public key Telegram tidak ditemukan."
        );

    }

    const publicKey =
        crypto.createPublicKey({
            key: jwk,
            format: "jwk"
        });

    const verifier =
        crypto.createVerify(
            "RSA-SHA256"
        );

    verifier.update(
        parts[0] +
        "." +
        parts[1]
    );

    verifier.end();

    const valid =
        verifier.verify(
            publicKey,
            Buffer
                .from(
                    parts[2],
                    "base64url"
                )
        );

    if(!valid){

        throw new Error(
            "Signature Telegram tidak valid."
        );

    }

    return payload;

}


async function checkChannelMembership(
    userId
){

    const response =
        await fetch(
            `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getChatMember`,
            {
                method:"POST",

                headers:{
                    "Content-Type":
                        "application/json"
                },

                body:JSON.stringify({
                    chat_id:
                        TELEGRAM_CHANNEL,

                    user_id:
                        Number(userId)
                })
            }
        );

    const data =
        await response.json();

    if(!data.ok){

        throw new Error(
            data.description ||
            "Telegram Bot API error."
        );

    }

    const status =
        data.result?.status;

    return [
        "creator",
        "administrator",
        "member"
    ].includes(status);

}


async function exchangeCode(
    code,
    redirectUri,
    verifier
){

    const credentials =
        Buffer
            .from(
                `${TELEGRAM_CLIENT_ID}:${TELEGRAM_CLIENT_SECRET}`
            )
            .toString("base64");

    const body =
        new URLSearchParams({

            grant_type:
                "authorization_code",

            code:
                code,

            redirect_uri:
                redirectUri,

            client_id:
                String(
                    TELEGRAM_CLIENT_ID
                ),

            code_verifier:
                verifier

        });

    const response =
        await fetch(
            "https://oauth.telegram.org/token",
            {
                method:"POST",

                headers:{
                    "Content-Type":
                        "application/x-www-form-urlencoded",

                    "Authorization":
                        `Basic ${credentials}`
                },

                body:
                    body.toString()
            }
        );

    const data =
        await response.json();

    if(!response.ok){

        throw new Error(
            data.error_description ||
            data.error ||
            "Gagal menukar authorization code."
        );

    }

    return data;

}


module.exports = async function handler(
    req,
    res
){

    try{

        if(req.method !== "GET" &&
           req.method !== "POST"){

            return res.status(405).json({
                success:false,
                message:"Method tidak diizinkan."
            });

        }


        if(
            !TELEGRAM_CLIENT_ID ||
            !TELEGRAM_CLIENT_SECRET ||
            !TELEGRAM_BOT_TOKEN
        ){

            return res.status(500).json({
                success:false,
                message:
                    "Environment Telegram belum lengkap."
            });

        }


        const url =
            new URL(
                req.url,
                `https://${req.headers.host}`
            );

        const action =
            url.searchParams.get("action");


        /*
        =========================================
        LOGIN
        =========================================
        */

        if(action === "login"){

            const state =
                randomString();

            const verifier =
                randomString();

            const challenge =
                sha256Base64url(
                    verifier
                );

            const redirectUri =
                `${url.origin}/api/verify-telegram?action=callback`;


            setCookie(
                res,
                "tg_state",
                state,
                {
                    maxAge:600
                }
            );


            setCookie(
                res,
                "tg_verifier",
                verifier,
                {
                    maxAge:600
                }
            );


            const authUrl =
                new URL(
                    "https://oauth.telegram.org/auth"
                );

            authUrl.searchParams.set(
                "client_id",
                String(
                    TELEGRAM_CLIENT_ID
                )
            );

            authUrl.searchParams.set(
                "redirect_uri",
                redirectUri
            );

            authUrl.searchParams.set(
                "response_type",
                "code"
            );

            authUrl.searchParams.set(
                "scope",
                "openid profile"
            );

            authUrl.searchParams.set(
                "state",
                state
            );

            authUrl.searchParams.set(
                "code_challenge",
                challenge
            );

            authUrl.searchParams.set(
                "code_challenge_method",
                "S256"
            );


            res.writeHead(
                302,
                {
                    Location:
                        authUrl.toString()
                }
            );

            return res.end();

        }


        /*
        =========================================
        CALLBACK
        =========================================
        */

        if(action === "callback"){

            const code =
                url.searchParams.get(
                    "code"
                );

            const state =
                url.searchParams.get(
                    "state"
                );

            const error =
                url.searchParams.get(
                    "error"
                );


            if(error){

                return res.redirect(
                    "/?telegram_error=" +
                    encodeURIComponent(
                        error
                    )
                );

            }


            const cookies =
                parseCookies(req);


            if(
                !state ||
                !cookies.tg_state ||
                state !== cookies.tg_state
            ){

                return res.status(400).send(
                    "Telegram login gagal: state tidak valid."
                );

            }


            if(!code){

                return res.status(400).send(
                    "Telegram login gagal: authorization code tidak ditemukan."
                );

            }


            const verifier =
                cookies.tg_verifier;


            const redirectUri =
                `${url.origin}/api/verify-telegram?action=callback`;


            const tokenData =
                await exchangeCode(
                    code,
                    redirectUri,
                    verifier
                );


            if(!tokenData.id_token){

                throw new Error(
                    "Telegram tidak mengembalikan ID token."
                );

            }


            const telegram =
                await verifyTelegramIdToken(
                    tokenData.id_token
                );


            const userId =
                telegram.id ||
                telegram.sub;


            if(!userId){

                throw new Error(
                    "Telegram User ID tidak ditemukan."
                );

            }


            const session =
                signSession({

                    id:
                        Number(userId),

                    name:
                        telegram.name ||
                        telegram.given_name ||
                        "Telegram User",

                    username:
                        telegram.preferred_username ||
                        "",

                    exp:
                        Date.now() +
                        60 * 60 * 1000

                });


            setCookie(
                res,
                "cotance_session",
                session,
                {
                    maxAge:
                        60 * 60
                }
            );


            setCookie(
                res,
                "tg_state",
                "",
                {
                    maxAge:0
                }
            );


            setCookie(
                res,
                "tg_verifier",
                "",
                {
                    maxAge:0
                }
            );


            return res.redirect(
                "/?telegram_login=success"
            );

        }


        /*
        =========================================
        VERIFY MEMBERSHIP
        =========================================
        */

        if(action === "verify"){

            const cookies =
                parseCookies(req);


            const session =
                verifySession(
                    cookies.cotance_session
                );


            if(!session){

                return res.status(401).json({
                    success:false,
                    verified:false,
                    message:
                        "Sesi Telegram belum tersedia."
                });

            }


            const joined =
                await checkChannelMembership(
                    session.id
                );


            if(!joined){

                return res.status(200).json({

                    success:false,

                    verified:false,

                    message:
                        "Kamu belum bergabung ke channel Telegram."

                });

            }


            const owner =
                String(session.id) ===
                OWNER_ID;


            return res.status(200).json({

                success:true,

                verified:true,

                owner:owner,

                user:{

                    id:
                        session.id,

                    name:
                        session.name,

                    username:
                        session.username

                },

                message:
                    "Verifikasi berhasil."

            });

        }


        /*
        =========================================
        SESSION INFO
        =========================================
        */

        if(action === "session"){

            const cookies =
                parseCookies(req);

            const session =
                verifySession(
                    cookies.cotance_session
                );

            if(!session){

                return res.status(200).json({
                    loggedIn:false
                });

            }

            return res.status(200).json({

                loggedIn:true,

                user:{
                    id:session.id,
                    name:session.name,
                    username:session.username
                }

            });

        }


        return res.status(400).json({

            success:false,

            message:
                "Action tidak dikenal."

        });


    }catch(error){

        console.error(
            "TELEGRAM ERROR:",
            error
        );

        return res.status(500).json({

            success:false,

            verified:false,

            message:
                error.message ||
                "Terjadi kesalahan server."

        });

    }

};
