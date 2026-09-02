import crypto from "crypto";

export default async function handler(req, res) {

    if (req.method !== "POST") {
        return res.status(405).json({
            success: false,
            message: "Method not allowed"
        });
    }

    try {

        const {
            id,
            first_name,
            last_name,
            username,
            photo_url,
            auth_date,
            hash
        } = req.body || {};

        if (!id || !auth_date || !hash) {
            return res.status(400).json({
                success: false,
                message: "Data Telegram tidak lengkap."
            });
        }

        const BOT_TOKEN =
            process.env.TELEGRAM_BOT_TOKEN;

        const CHANNEL =
            process.env.TELEGRAM_CHANNEL ||
            "@allaboutxlilnyx";

        if (!BOT_TOKEN) {
            return res.status(500).json({
                success: false,
                message:
                    "TELEGRAM_BOT_TOKEN belum dikonfigurasi."
            });
        }

        /* CEK AUTH DATE */

        const now =
            Math.floor(Date.now() / 1000);

        const authTime =
            Number(auth_date);

        if (
            !Number.isFinite(authTime) ||
            Math.abs(now - authTime) > 600
        ) {

            return res.status(401).json({
                success: false,
                message:
                    "Login Telegram sudah kedaluwarsa."
            });

        }

        /* VALIDASI HASH */

        const dataCheckString =
            Object.keys(req.body)
                .filter(
                    key => key !== "hash"
                )
                .sort()
                .map(
                    key =>
                        `${key}=${req.body[key]}`
                )
                .join("\n");

        const secretKey =
            crypto
                .createHash("sha256")
                .update(BOT_TOKEN)
                .digest();

        const calculatedHash =
            crypto
                .createHmac(
                    "sha256",
                    secretKey
                )
                .update(dataCheckString)
                .digest("hex");

        if (calculatedHash !== hash) {

            return res.status(401).json({
                success: false,
                message:
                    "Validasi identitas Telegram gagal."
            });

        }

        /* CEK MEMBERSHIP */

        const telegramURL =
            `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember` +
            `?chat_id=${encodeURIComponent(CHANNEL)}` +
            `&user_id=${encodeURIComponent(id)}`;

        const response =
            await fetch(telegramURL);

        const data =
            await response.json();

        if (!data.ok) {

            console.error(
                "Telegram API:",
                data
            );

            return res.status(400).json({
                success: false,
                message:
                    "Gagal memeriksa membership Telegram.",
                error:
                    data.description ||
                    "Unknown Telegram error"
            });

        }

        const memberStatus =
            data.result?.status;

        const verified =
            memberStatus === "member" ||
            memberStatus === "administrator" ||
            memberStatus === "creator";

        /* OWNER */

        const OWNER_ID =
            "6282298313";

        const isOwner =
            String(id) === OWNER_ID;

        /* VERIFIED */

        if (verified) {

            return res.status(200).json({

                success: true,

                verified: true,

                telegram_connected: true,

                owner: isOwner,

                user: {
                    id: String(id),
                    first_name:
                        first_name || "",
                    last_name:
                        last_name || "",
                    username:
                        username || "",
                    photo_url:
                        photo_url || ""
                },

                status:
                    memberStatus,

                message:
                    isOwner
                        ? "OWNER berhasil diverifikasi."
                        : "Telegram berhasil diverifikasi."

            });

        }

        return res.status(200).json({

            success: true,

            verified: false,

            telegram_connected: true,

            owner: isOwner,

            status:
                memberStatus,

            message:
                "Akun Telegram terdeteksi, tetapi belum bergabung ke channel."

        });

    } catch (error) {

        console.error(
            "VERIFY ERROR:",
            error
        );

        return res.status(500).json({
            success: false,
            message:
                "Terjadi kesalahan pada server."
        });

    }

}
