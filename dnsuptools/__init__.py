#!/usr/bin/env python3
# -*- encoding: UTF8 -*-

import git

repo = git.Repo(search_parent_directories=False)

__version__ = '-'.join(repo.git.describe('--tags').split('-')[:2])


