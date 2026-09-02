const crypto = require("crypto");

const TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHANNEL = process.env.TELEGRAM_CHANNEL || "@allaboutxlilnyx";

function sign(data) {
    return crypto
        .createHmac("sha256", TOKEN)
        .update(data)
        .digest("base64url");
}

function verifyToken(token) {
    try {
        const [data, signature] = token.split(".");

        if (!data || !signature) return null;

        const expected = sign(data);

        if (
            !crypto.timingSafeEqual(
                Buffer.from(signature),
                Buffer.from(expected)
            )
        ) {
            return null;
        }

        const payload = JSON.parse(
            Buffer.from(data, "base64url").toString()
        );

        if (!payload.id || !payload.exp) return null;

        if (Math.floor(Date.now() / 1000) > payload.exp) {
            return null;
        }

        return payload;

    } catch {
        return null;
    }
}

async function checkMember(userId) {

    const url =
        `https://api.telegram.org/bot${TOKEN}/getChatMember` +
        `?chat_id=${encodeURIComponent(CHANNEL)}` +
        `&user_id=${encodeURIComponent(userId)}`;

    const response = await fetch(url);
    const data = await response.json();

    if (!data.ok) {
        throw new Error(
            data.description || "Telegram API error"
        );
    }

    const member = data.result;

    const verified =
        member.status === "member" ||
        member.status === "administrator" ||
        member.status === "creator" ||
        (
            member.status === "restricted" &&
            member.is_member === true
        );

    return {
        verified,
        status: member.status
    };
}

function setCookie(value) {
    return [
        `cotance_session=${value}`,
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=604800"
    ].join("; ");
}

function clearCookie() {
    return [
        "cotance_session=",
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=0"
    ].join("; ");
}

function getCookie(req, name) {

    const cookie = req.headers.cookie || "";

    const match = cookie
        .split(";")
        .map(x => x.trim())
        .find(x => x.startsWith(name + "="));

    return match
        ? decodeURIComponent(
            match.substring(name.length + 1)
        )
        : null;
}

module.exports = async function handler(req, res) {

    if (!TOKEN) {
        return res.status(500).json({
            success: false,
            message: "TELEGRAM_BOT_TOKEN belum diatur."
        });
    }

    const action =
        req.query.action || "verify";


    /* ==============================
       CLAIM VERIFICATION
    ============================== */

    if (action === "claim") {

        const token =
            req.body?.token ||
            req.query.token;

        if (!token) {

            return res.status(400).json({
                success: false,
                verified: false,
                message: "Token verifikasi tidak ditemukan."
            });

        }

        const payload =
            verifyToken(token);

        if (!payload) {

            return res.status(401).json({
                success: false,
                verified: false,
                message: "Token verifikasi tidak valid atau sudah kedaluwarsa."
            });

        }

        try {

            const result =
                await checkMember(payload.id);

            if (!result.verified) {

                return res.status(403).json({
                    success: false,
                    verified: false,
                    message: "Akun Telegram belum bergabung dengan channel."
                });

            }

            const sessionData = Buffer
                .from(JSON.stringify({
                    id: String(payload.id),
                    exp:
                        Math.floor(Date.now() / 1000) +
                        604800
                }))
                .toString("base64url");

            const session =
                `${sessionData}.${sign(sessionData)}`;

            res.setHeader(
                "Set-Cookie",
                setCookie(session)
            );

            return res.status(200).json({
                success: true,
                verified: true,
                message: "Verifikasi berhasil."
            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                success: false,
                verified: false,
                message: "Gagal mengecek membership Telegram."
            });

        }
    }


    /* ==============================
       VERIFY SESSION
    ============================== */

    if (action === "verify") {

        const session =
            getCookie(req, "cotance_session");

        if (!session) {

            return res.status(200).json({
                success: false,
                verified: false,
                message: "Belum terverifikasi."
            });

        }

        const payload =
            verifyToken(session);

        if (!payload) {

            res.setHeader(
                "Set-Cookie",
                clearCookie()
            );

            return res.status(200).json({
                success: false,
                verified: false,
                message: "Sesi sudah kedaluwarsa."
            });

        }

        try {

            const result =
                await checkMember(payload.id);

            if (!result.verified) {

                res.setHeader(
                    "Set-Cookie",
                    clearCookie()
                );

                return res.status(200).json({
                    success: false,
                    verified: false,
                    message: "Kamu sudah tidak menjadi member channel."
                });

            }

            return res.status(200).json({
                success: true,
                verified: true,
                telegram_id: payload.id,
                status: result.status
            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                success: false,
                verified: false,
                message: "Gagal mengecek membership."
            });
        }
    }


    /* ==============================
       LOGOUT
    ============================== */

    if (action === "logout") {

        res.setHeader(
            "Set-Cookie",
            clearCookie()
        );

        return res.status(200).json({
            success: true
        });
    }


    return res.status(400).json({
        success: false,
        message: "Action tidak dikenal."
    });
};
