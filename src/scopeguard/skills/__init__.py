"""Skills are pure functions: cleaned data in, text out.

They import nothing that can touch files, the network or the OS. This is enforced
by tests/test_skills_are_pure.py, which checks every module in this folder against
an import allow-list.
"""
