const crypto = require("crypto");

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHANNEL = process.env.TELEGRAM_CHANNEL || "@allaboutxlilnyx";

const OWNER_ID = "6282298313";

function parseCookies(req) {
    const header = req.headers.cookie || "";
    const cookies = {};

    header.split(";").forEach(part => {
        const index = part.indexOf("=");

        if (index === -1) return;

        const key = part.slice(0, index).trim();
        const value = part.slice(index + 1).trim();

        cookies[key] = decodeURIComponent(value);
    });

    return cookies;
}

function setCookie(res, name, value, maxAge = 3600) {
    const cookie =
        `${name}=${encodeURIComponent(value)}` +
        `; Path=/` +
        `; Max-Age=${maxAge}` +
        `; HttpOnly` +
        `; SameSite=Lax` +
        `; Secure`;

    res.setHeader("Set-Cookie", cookie);
}

function createSession(user) {
    const payload = {
        id: Number(user.id),
        name: user.first_name || user.name || "Telegram User",
        username: user.username || "",
        exp: Date.now() + 60 * 60 * 1000
    };

    const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");

    const signature = crypto
        .createHmac("sha256", BOT_TOKEN)
        .update(encoded)
        .digest("hex");

    return `${encoded}.${signature}`;
}

function verifySession(token) {
    if (!token) return null;

    const parts = token.split(".");

    if (parts.length !== 2) return null;

    const encoded = parts[0];
    const signature = parts[1];

    const expected = crypto
        .createHmac("sha256", BOT_TOKEN)
        .update(encoded)
        .digest("hex");

    if (signature.length !== expected.length) {
        return null;
    }

    if (
        !crypto.timingSafeEqual(
            Buffer.from(signature),
            Buffer.from(expected)
        )
    ) {
        return null;
    }

    try {
        const payload = JSON.parse(
            Buffer.from(encoded, "base64url").toString("utf8")
        );

        if (!payload.exp || Date.now() >= payload.exp) {
            return null;
        }

        return payload;

    } catch {
        return null;
    }
}

/*
 * Validasi data Telegram Login Widget.
 *
 * Telegram mengirim:
 * id
 * first_name
 * last_name
 * username
 * photo_url
 * auth_date
 * hash
 *
 * Hash dihitung menggunakan:
 *
 * SHA256(BOT_TOKEN)
 *
 * sebagai secret HMAC-SHA256.
 */
function verifyTelegramAuth(data) {
    if (!data || !data.hash || !data.id || !data.auth_date) {
        return false;
    }

    const authDate = Number(data.auth_date);

    if (!Number.isFinite(authDate)) {
        return false;
    }

    /*
     * Tolak data login yang terlalu lama.
     * 1 jam.
     */
    const now = Math.floor(Date.now() / 1000);

    if (Math.abs(now - authDate) > 3600) {
        return false;
    }

    const dataCheckString = Object.keys(data)
        .filter(key => key !== "hash")
        .sort()
        .map(key => `${key}=${data[key]}`)
        .join("\n");

    const secretKey = crypto
        .createHash("sha256")
        .update(BOT_TOKEN)
        .digest();

    const calculatedHash = crypto
        .createHmac("sha256", secretKey)
        .update(dataCheckString)
        .digest("hex");

    if (calculatedHash.length !== data.hash.length) {
        return false;
    }

    return crypto.timingSafeEqual(
        Buffer.from(calculatedHash, "hex"),
        Buffer.from(data.hash, "hex")
    );
}

async function checkChannelMembership(userId) {
    const response = await fetch(
        `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember`,
        {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                chat_id: CHANNEL,
                user_id: Number(userId)
            })
        }
    );

    const data = await response.json();

    if (!data.ok) {
        throw new Error(
            data.description || "Gagal mengecek membership Telegram."
        );
    }

    const status = data.result?.status;

    return [
        "creator",
        "administrator",
        "member"
    ].includes(status);
}

module.exports = async function handler(req, res) {

    try {

        if (!BOT_TOKEN) {
            return res.status(500).json({
                success: false,
                message: "TELEGRAM_BOT_TOKEN belum diatur di Vercel."
            });
        }

        if (req.method !== "POST" && req.method !== "GET") {
            return res.status(405).json({
                success: false,
                message: "Method tidak diizinkan."
            });
        }

        const url = new URL(
            req.url,
            `https://${req.headers.host}`
        );

        const action = url.searchParams.get("action");

        /*
         * ==========================================
         * LOGIN
         * ==========================================
         */

        if (action === "login") {

            return res.status(200).json({
                success: true,
                message: "Gunakan tombol Login Telegram pada halaman."
            });
        }

        /*
         * ==========================================
         * AUTH
         * ==========================================
         */

        if (action === "auth") {

            let data = req.body;

            if (typeof data === "string") {
                try {
                    data = JSON.parse(data);
                } catch {
                    data = null;
                }
            }

            if (!data) {
                return res.status(400).json({
                    success: false,
                    verified: false,
                    message: "Data Telegram tidak ditemukan."
                });
            }

            /*
             * Pastikan data benar-benar berasal
             * dari Telegram.
             */
            if (!verifyTelegramAuth(data)) {

                return res.status(401).json({
                    success: false,
                    verified: false,
                    message: "Data login Telegram tidak valid."
                });
            }

            /*
             * Cek membership channel.
             */
            const joined = await checkChannelMembership(data.id);

            if (!joined) {

                return res.status(403).json({
                    success: false,
                    verified: false,
                    joined: false,
                    message:
                        "Kamu belum bergabung ke channel Telegram."
                });
            }

            /*
             * Buat session server.
             */
            const session = createSession(data);

            setCookie(
                res,
                "cotance_session",
                session,
                60 * 60
            );

            const owner =
                String(data.id) === OWNER_ID;

            return res.status(200).json({
                success: true,
                verified: true,
                owner,

                user: {
                    id: Number(data.id),
                    name:
                        data.first_name ||
                        data.username ||
                        "Telegram User",

                    username:
                        data.username || ""
                },

                message: "Verifikasi berhasil."
            });
        }

        /*
         * ==========================================
         * VERIFY SESSION
         * ==========================================
         */

        if (action === "verify") {

            const cookies = parseCookies(req);

            const session = verifySession(
                cookies.cotance_session
            );

            if (!session) {

                return res.status(401).json({
                    success: false,
                    verified: false,
                    message: "Belum login Telegram."
                });
            }

            /*
             * Cek membership lagi.
             */
            const joined =
                await checkChannelMembership(session.id);

            if (!joined) {

                return res.status(403).json({
                    success: false,
                    verified: false,
                    message:
                        "Kamu sudah tidak tergabung di channel."
                });
            }

            const owner =
                String(session.id) === OWNER_ID;

            return res.status(200).json({
                success: true,
                verified: true,
                owner,

                user: {
                    id: session.id,
                    name: session.name,
                    username: session.username
                },

                message: "Verifikasi berhasil."
            });
        }

        /*
         * ==========================================
         * SESSION
         * ==========================================
         */

        if (action === "session") {

            const cookies = parseCookies(req);

            const session = verifySession(
                cookies.cotance_session
            );

            if (!session) {

                return res.status(200).json({
                    loggedIn: false
                });
            }

            return res.status(200).json({
                loggedIn: true,

                user: {
                    id: session.id,
                    name: session.name,
                    username: session.username
                }
            });
        }

        /*
         * ==========================================
         * LOGOUT
         * ==========================================
         */

        if (action === "logout") {

            setCookie(
                res,
                "cotance_session",
                "",
                0
            );

            return res.status(200).json({
                success: true,
                message: "Logout berhasil."
            });
        }

        return res.status(400).json({
            success: false,
            message: "Action tidak dikenal."
        });

    } catch (error) {

        console.error(
            "TELEGRAM VERIFY ERROR:",
            error
        );

        return res.status(500).json({
            success: false,
            verified: false,
            message:
                error.message ||
                "Terjadi kesalahan server."
        });
    }
};
