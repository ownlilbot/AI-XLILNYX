export default async function handler(req, res) {
    // Hanya menerima POST
    if (req.method !== "POST") {
        return res.status(405).json({
            success: false,
            message: "Method not allowed"
        });
    }

    try {
        const { user_id } = req.body || {};

        // Cek Telegram User ID
        if (!user_id) {
            return res.status(400).json({
                success: false,
                message: "Telegram User ID tidak ditemukan."
            });
        }

        // Ambil dari Vercel Environment Variables
        const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
        const CHANNEL = process.env.TELEGRAM_CHANNEL || "@allaboutxlilnyx";

        if (!BOT_TOKEN) {
            return res.status(500).json({
                success: false,
                message: "TELEGRAM_BOT_TOKEN belum dikonfigurasi di Vercel."
            });
        }

        // Panggil Telegram Bot API
        const telegramURL =
            `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember` +
            `?chat_id=${encodeURIComponent(CHANNEL)}` +
            `&user_id=${encodeURIComponent(user_id)}`;

        const response = await fetch(telegramURL);
        const data = await response.json();

        // Telegram API error
        if (!data.ok) {
            console.error("Telegram API:", data);

            return res.status(400).json({
                success: false,
                message: "Gagal memeriksa membership Telegram.",
                error: data.description || "Unknown Telegram error"
            });
        }

        const status = data.result?.status;

        // Status yang dianggap sudah bergabung
        const verified =
            status === "member" ||
            status === "administrator" ||
            status === "creator";

        if (verified) {
            return res.status(200).json({
                success: true,
                verified: true,
                status: status,
                message: "Telegram berhasil diverifikasi."
            });
        }

        // Belum join / sudah keluar
        return res.status(200).json({
            success: true,
            verified: false,
            status: status,
            message: "Kamu belum bergabung ke channel Telegram."
        });

    } catch (error) {
        console.error("VERIFY ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Terjadi kesalahan pada server."
        });
    }
