---
title: Contribution
keywords: contribution
sidebar: mydoc_sidebar
permalink: contribution.html
folder: mydoc
---

## Introduction

We use simplified [GitFlow branching model](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow) for Dow Jones Hammer development.

Instead of a single `master` branch, this workflow uses two branches to record the history of the project. The `master` branch stores the official release history, and the `dev` branch serves as an integration branch for features.

Each new feature should reside in its own branch. But, instead of branching off of `master`, **feature** branches use `dev` as their parent branch. When a feature is completed, it gets merged back into `dev`. Features should never interact directly with `master`.


## How to report a bug

* Ensure the bug was not already reported by searching on GitHub under Issues.
* If you're unable to find an open issue addressing the problem, open a new one. Be sure to include a title and clear description, as much relevant information as possible, and a code sample or an executable test case demonstrating the expected behavior that is not occurring.


## How to suggest your changes

* Open a new GitHub pull request with the patch.
* Ensure the PR description clearly describes the problem and solution. Include the relevant issue number if applicable.


## Contacts

Feel free to email us at [hammer@dowjones.com](mailto:hammer@dowjones.com) with any other questions or concerns you have.