# r2bot
An IRCbot that uses r2pipe to do collaborative reversing and program analysis.

The usage of the bot is as follows:

1. You can create what is considered "projects".
  * Projects are individual objects that contain information such as a python r2pipe, users in the project, and path to ELF file.
2. You can "join" a project by using the joinproject command.
  * Joining projects allows a user to be able to issue commands to r2bot. Any command that is given to r2bot that isn't predefined
  is considered a command directly to r2pipe. Output will be displayed in IRC.
  * You can only be in one project at a time. Joining another project will remove yourself from any previous projects.
3. You can see information in a project by issuing the command projectinfo.
  * This will tell you the users in the project, path and project name.
4. A project can be deleted by using the command closeproject.
5. You can add the field -all e.g. "r2bot: -all pdf@main" to a command to tell r2bot to list all that it possibly can.
  * This is not quite as much as it can as it is limited to 75 lines total no matter what. This will prevent unintentional "spam"
  entering a channel. Without the -all field added to a command the bot will print out 10 lines at time. This can be changed
  using the setlimit command which can go up to 30 lines per command.
6. Information on how to use the bot is acquired by using the help command or the man command.
  * E.g. "r2bot: help joinproject" which will return pydoc information about the method.
  * The command man returns all the available commands that r2bot can perform.

# Improvements:
1. Make it possible to issue a "stop" command to r2bot while printing so that users may stop it if they have at a certain point
  acquired all the information they need. This will prevent "spam" like output.
2. Another solution may involve r2bot creating a new IRC channel specific to the project and then invite users to join that channel.
