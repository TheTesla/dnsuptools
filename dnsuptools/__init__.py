#!/usr/bin/env python3
# -*- encoding: UTF8 -*-

repo = git.Repo(search_parent_directories=False)

version = repo.tags[-1].name if repo.head.commit == repo.tags[-1].commit else str(repo.tags[-1].name) +"~"+ str(repo.head.commit.authored_date) if len(repo.tags) > 0 else repo.head.commit

__version__ =  version


