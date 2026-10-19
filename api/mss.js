// Monitor Saham Syariah - satu Vercel Function untuk halaman aplikasi, login, admin, dan data live.
// Didisain oleh @letsgobram - @motivaseein
// Memakai ekspor "fetch" (Web Standard): fungsi menerima Request dan mengembalikan Response.
import { handle } from "../server/app.mjs";

export default {
  async fetch(request) {
    try {
      return await handle(request, {});
    } catch (e) {
      console.error(e);
      return new Response(JSON.stringify({ error: "Server error: " + String((e && e.message) || e).slice(0, 200) }), {
        status: 500, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
      });
    }
  },
};
