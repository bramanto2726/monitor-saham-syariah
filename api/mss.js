// Monitor Saham Syariah - satu Vercel Function untuk halaman aplikasi, login, admin, dan data live.
// Didisain oleh @letsgobram - @motivaseein
import { handle } from "../server/app.mjs";

export default async function handler(request) {
  return handle(request, {});
}
