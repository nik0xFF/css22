# Cyber Security Specialist 2022
Preparational work for swiss federal diploma

## Notes on colaboration 
### Using Git
For those of you not having any experience with using git from the shell of choice, I recommend you download Pycharm Community Edition https://www.jetbrains.com/pycharm/download/#section=windows
It offers a well integrated Git client and the option to access github with your credentials.

I would consider it as good practice if we employ some basic constraints when collaborating on this matter. 
If you have a new recipe, script or want to extend an existing one, you should create a new branch, prefixed with **feature/**, followed by the tech/category, a 3 digit number and the name
I think we should be able to keep track on the sequence of numbers by checking the existing branches and mains content. 

f.e. 
* feature/bash-001-unstructured-log-file-joiner
* feature/recipe-001-nwta-get-email-attachments-from-pcap

If you found an error, you create a new branch prefixed with **bugfix/**, followed by category and the number of the affected feature
* bugfix/bash-001-missing-win-newline-handling
* bugfix/recipe-001-error-in-smtp-filter

If you want to add inline comments or documentation, I suggest we use a third prefix **comment/** 

Please note that committing to main has been disabled, any feature or bugfix requires a pull request. The PR must be reviewed by at least one other person before it can be merged. 
After merging you should delete your branch.

### Recipes and Documentation 

I think we should stick to plain *.md files. 
The syntax may be found here https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax

## Table of contents 
- [bash](bash)
