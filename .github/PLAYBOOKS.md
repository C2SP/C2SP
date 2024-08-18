# New Specification Playbook

Stewards follow these instructions when creating a new spec, after it was
approved per the process in [CONTRIBUTING](CONTRIBUTING.md#new-specifications).

* Create a new [@C2SP/maintainers sub-team](https://github.com/orgs/C2SP/teams)
  and add the new maintainers. If any maintainers are new to C2SP, see the New
  Maintainer Playbook.

* Create an empty `<spec-name>.md` file.

* Run `cd .github && go generate ./...`.

* Update `.github/README.md` to add the new spec.

* Open a PR with all the changes above, mark it "Closes #NNN" for the issue
  number requesting the new spec, and have it approved by another steward.

# New Maintainer Playbook

Stewards follow these instructions when onboarding a new maintainer for a spec.

* Add the maintainer to the [relevant @C2SP/maintainers
  sub-team](https://github.com/orgs/C2SP/teams). This will grant them write
  access automatically.

* Send the following intro to the maintainer.

  > Welcome to C2SP and thank you for maintaining a spec!
  >
  > You now have access to approve and merge any PR to your spec (both the `.md` file in the
  > root of the repository and anything under a directory named like your spec), as well as
  > to manage the issue tracker. Please only take maintainer actions on issues related to your
  > spec.
  >
  > Note that GitHub paths are not stable: please use the c2sp.org redirector when possible.
  > `c2sp.org/<spec>` redirects to your spec, and `c2sp.org/CCTV/<spec>` redirects to
  > the CCTV vectors, if any.
  > 
  > Let us know if you encounter any issues.
