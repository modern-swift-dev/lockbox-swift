# Contributing

## Website releases

The generated website in `docs/` is committed to the repository. `make site-build` replaces that directory only after the Astro build, DocC build, and internal-link check pass. After publishing a GitHub release:

1. Run `make site-setup` to install the locked website dependencies.
2. Run `make site-build` to fetch the latest published release and rebuild the Astro and DocC output.
3. Run `make site-preview`, then review the release details, responsive pages, and generated API documentation at `http://localhost:8000/lockbox-swift/`.
4. Stop the preview, run `make site-validate`, review `git diff`, and commit the updated `docs/` output with the source changes.

GitHub Pages requires one manual repository setting. Under **Settings > Pages**, choose **Deploy from a branch**, select `main` and `/docs`, then save. The build does not change this setting. See GitHub's [branch publishing instructions](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site).
