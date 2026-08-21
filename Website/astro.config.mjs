import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  site: "https://modern-swift-dev.github.io",
  base: "/lockbox-swift",
  output: "static",
  vite: {
    plugins: [tailwindcss()]
  }
});
