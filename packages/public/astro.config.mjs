// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import pagefind from 'astro-pagefind';

// https://astro.build/config
export default defineConfig({
  site: 'https://blog.leyanwc.xyz',
  output: 'static',

  // Pagefind：构建期静态索引，只含 L0 公开内容（② 站内搜索）
  integrations: [
    pagefind(),
    sitemap({
      filter: (page) => !page.includes('/404') && !page.includes('/pagefind/'),
    }),
  ],
});