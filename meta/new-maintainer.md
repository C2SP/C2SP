# New Maintainer Playbook

Stewards follow these instructions when onboarding a new maintainer for a spec.

* [Add the maintainer to the C2SP/C2SP repository with Write permissions.](https://github.com/C2SP/C2SP/settings/access)
* Add two lines to [CODEOWNERS](https://github.com/C2SP/C2SP/blob/main/CODEOWNERS).

  ```
  <slug>.md @<maintainer>
  <slug>/   @<maintainer>
  ```

* If applicable, repeat the process for [the CCTV repository](https://github.com/C2SP/CCTV).
* Send the following intro to the maintainer.

  > Welcome to C2SP and thank you for maintaining a new spec!
  >
  > You now have access to approve and merge any PR to your spec (both the `.md` file in the
  > root of the repository and anything under a directory named like your spec), as well as
  > to manage the issue tracker. Please only take maintainer actions on issues related to your
  > spec.
  >
  > Note that GitHub paths are not stable: please use the c2sp.org redirector when possible.
  > `c2sp.org/<spec>` redirects to your spec, and `c2sp.org/CCTV/<spec>` redirects to
  > the CCTV vectors.
  > 
  > Let us know if you encounter any issues.
