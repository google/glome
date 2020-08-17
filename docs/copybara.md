# GLOME Copybara Setup

go/glome-copybara

<!--*
# Document freshness: For more information, see go/fresh-source.
freshness: { owner: 'markusrudy' reviewed: '2020-08-13' }
*-->

[TOC]

## Troubleshooting

### Accidental merge on Github instead of Piper

**Symptom**:
[postsubmit_piper_to_github](http://copybara/list-jobs?piperConfigPath=%2F%2Fdepot%2Fgoogle3%2Fthird_party%2Fglome%2Fcopy.bara.sky&workflowName=postsubmit_piper_to_github)
fails with a merge conflict.

**Root cause**: A PR has been merged directly on Github and was submitted to
Piper afterwards, instead of being submitted to Piper first and automatically
merged by Copybara afterwards.

**The problem**: Copybara tracks its synchronization by tagging CLs and PRs with
the equivalent commit hash and revision number, respectively. If a commit is
merged on Github, it is not tagged with its CL equivalent. If that CL is now
submitted to Piper, Copybara will try to rebase its contents onto the master
branch, which will result in a merge conflict preventing the post-submit from
happening. That post-submit is responsible for maintaining the association
between CL and git commit, so subsequent PRs/CLs will also not know about the
synchronization state (which is in fact fine) and fail as well.

**Mitigation**:

1.  Track down all changes in Github that do *not* have a `PiperOrigin-RevID`
    tag set until you encounter a commit that does.
2.  Find the highest CL number that corresponds to one of these changes and is
    submitted.
3.  Create an empty commit on the master branch that makes Copybara aware of the
    synchronization status, push it directly to Github. ```shell git checkout
    master && git pull --ff origin master && \
    git commit --allow-empty -m "copybara: fix synchronization

    PiperOrigin-RevId: ${CL_NUMBER} " && git push origin master ```

4.  After submitting the next CL to Piper, Copybara should be working again. You
    can also run the workflow directly to see the results: `shell cd
    /google/src/head/depot/google3/third_party/glome && \ copybara
    ./copy.bara.sky postsubmit_piper_to_github`
