import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://cawalch.github.io',
  base: '/go-yara',
  trailingSlash: 'always',
  integrations: [starlight({
    title: 'go-yara',
    description: 'Compile YARA rules and scan data in Go, without CGO or libyara.',
    favicon: '/favicon.svg',
    social: [{ icon: 'github', label: 'Source on GitHub', href: 'https://github.com/cawalch/go-yara' }],
    sidebar: [
      { label: 'Overview', slug: '' },
      { label: 'Get started', items: [
        { label: 'Quickstart', slug: 'quickstart' },
        { label: 'Installation', slug: 'installation' },
      ] },
      { label: 'Use go-yara', items: [
        { label: 'Scanning', slug: 'scanning' },
        { label: 'Modules', slug: 'modules' },
        { label: 'Performance', slug: 'performance' },
      ] },
      { label: 'Reference', items: [
        { label: 'YARA compatibility', slug: 'compatibility' },
        { label: 'CLI', slug: 'cli' },
        { label: 'Releases and upgrades', slug: 'releases' },
      ] },
    ],
    editLink: { baseUrl: 'https://github.com/cawalch/go-yara/edit/main/site/' },
    customCss: ['./src/styles/custom.css'],
    components: { PageTitle: './src/components/PageTitle.astro' },
    head: [{ tag: 'meta', attrs: { name: 'theme-color', content: '#163d4d' } }],
  })],
});
