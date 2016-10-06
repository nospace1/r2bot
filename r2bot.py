#!/usr/bin/env python2
#needs to run as python2 as r2pipe is supported such
import socket
import time
import threading
import r2pipe
import re
import os

class Connection():
    def __init__(self, **kwargs):
        self.host = kwargs.get('host', 'localhost')
        self.port = kwargs.get('port', 6667)
        self.nick = kwargs.get('nick', 'undefined')
        self.chan = kwargs.get('channel', ['#5950', '#ctf'])
        self.ident = kwargs.get('ident', self.nick)
        self.realname = kwargs.get('realname', self.nick)
        self.sock = socket.socket()

    def setNick(self, nick):
        self.nick = nick
        self.sendraw("NICK {n}\r\n".format(n=nick))

    def connect(self):
        print("Connecting to server: " + self.host)
        self.sock.connect((self.host, self.port))
        data = self.sock.recv(4096).decode()

    def sendraw(self, string):
        #send a raw message to the server!
        print("\033[91m[>] {s}\033[0m".format(s=string))
        self.sock.send(string.encode())

    def register(self):
        #registers after connection?
        print("Sending Nick information")
        self.sendraw("NICK {n}\r\n".format(n=self.nick))
        print("Registering with identity {i} and name {n}" \
                .format(i=self.ident, n=self.realname))
        self.sendraw("USER {i} 0 * :{n}\r\n" \
                .format(i=self.ident, n=self.realname))

    def join(self, chan):
        self.sendraw("JOIN {ch}\r\n".format(ch=chan))

    def part(self, chan):
        self.sendraw("PART {ch}\r\n".format(ch=chan))

    def recieve(self):
        data = self.sock.recv(4096).decode()
        return data

    def privmsg(self, chan, message):
        msg = "PRIVMSG {ch} :{m}\r\n".format(ch=chan, m=message)
        self.sendraw(msg)

    def action(self, chan, action):
        act = "PRIVMSG {ch} :\x01ACTION {a}\r\n".format(ch=chan, a=action)
        self.sendraw(act)

    def pong(self, message):
#        print("I'm ponging: {m}".format(m=message))
        self.sendraw("PONG {m}\r\n".format(m=message))

    def lookup(self, user):
        self.sendraw("WHOIS {u}\r\n".format(u=user))

    def annoyHellbacon():
        '''sends stringy a message'''
        msg = "hi"
        msg = "PRIVMSG hellbacon :%s\r\n" % (msg)
        sendraw(msg)
        threading.Timer(5, annoyHellbacon).start()

    def timedEvent(function, interval):
        #call this function at a duration in the future
        threading.Timer(interval, function).start()

class Project():
    def __init__(self):
        self.name = ''
        self.filepath = None
        self.pipe = self.open(self.name)
        self.users = []

    def open(self, filepath):
        self.filepath = filepath
        self.name = os.path.basename(filepath)
        print("Opening pipe: " + self.filepath)
        self.pipe = r2pipe.open(self.filepath)
        #self.command('doo') #opens in debugging mode because why not

    def close(self):
        print("Closing pipe")
        self.pipe.quit()

    #performs command and returns data related to command as list of strings
    def command(self, cmd):
        print("Performing command: " + cmd)
        data = self.pipe.cmd(cmd).split("\n")
        return data

class MessageHandler():
    #regex it to get nick, username, server, message type,
    #   channel, and message
    #ex: bob!boberson@yakko.cs.wmich.edu PRIVMSG #asdf :testing
    def parse(self, data):
        #"borrowed" from stringy <3
        #   who probably "borrowed" it from someone else
        IRC_RE = re.compile(r'^(:(?P<prefix>\S+) )?(?P<command>\S+)' \
                          '( (?!:)(?P<params>.+?))?( :(?P<trail>.+))?$')
        match = IRC_RE.match(data)
        if match:
            ref = {'user':match.group('prefix'),
                    'mtype':match.group('command'),
                    'channel':match.group('params'),
                    'data':match.group('trail')}
            return ref
        else:
            #no match!
            ref = {'user':None,'mtype':None,'channel':None,'data':None}
            return ref

class Bot():
    def __init__(self):
        self.name = "r2bot"
        self.channels = ['#thedeeperpit']
        self.connection = None
        self.projects = {} #a buncha r2pipes with associated name
        self.lineLimit = 10

    def link(self):
        self.conn = Connection(nick=self.name)
        self.conn.connect()
        self.conn.register()

    def run(self):
        self.link()
        for chan in self.channels:
            self.joinChan(chan)
        self.listen()

    def joinChan(self, chan):
        self.conn.join(chan)

    def talk(self, chan, msg):
        self.conn.privmsg(chan, msg)

    def hasLeader(self, data):
        if(data.split(' ')[0].lower() == (self.name+':') or \
                data.split(' ')[0].lower() == self.name):
            return True
        else:
            return False

    def constructDict(self, who, where, data, bot):
        dataDict = {'who':who.split('!')[0], 'where':where, 'data':data, 'conn':self.conn, 'bot':bot}
        return dataDict

    #r2bot: addproject project1
    #name is path to file
    def addProject(self, dataDict):
        #check for duplicates
        projpath = dataDict['data'].split(' ')[2]
        projname = os.path.basename(projpath)
        if(projname in self.projects):
            self.talk(dataDict['where'], "Project already opened")
        else:
            #parse out command...
            #r2bot: newproject path/overflow
            p = Project()
            p.open(projpath)
            self.projects[p.name] = p

    #r2bot: changeproj proj1
    def joinProject(self, dataDict):
        #check to see if project exists
        pname = dataDict['data'].split(' ')[2]
        print(dataDict['who'] + " in channel " + dataDict['where'] + "attempting to join project " + pname)
        if(pname in self.projects):
            #check all projects for user, if found remove from proj
            for projname, proj in self.projects.iteritems():
                if(dataDict['who'] in proj.users):
                    proj.users.remove(dataDict['who'])
            #add user to new project
            for projname, proj in self.projects.iteritems():
                if(pname == projname):
                    proj.users.append(dataDict['who'])
        else:
            self.talk(dataDict['where'], "No project exists with that name")

    #r2bot: command stuff here
    def issueCommand(self, dataDict):
        #check to see if they are in a project
        #if(dataDict['who'] in self.projects):
        command = dataDict['data'].split(' ', 1)[1]
        print("command is: " + command)
        if(len(command) > 1):
            if('!' in command):
                self.talk(dataDict['where'], "! is not an allowed character")
            else:

                for projname, proj in self.projects.iteritems():
                    if(dataDict['who'] in proj.users):
                        lines = proj.command(command)
                        if(len(lines) > 0):
                            if(len(lines) > self.lineLimit):
                                for x in xrange(0,self.lineLimit):
                                    self.talk(dataDict['where'], lines[x])
                                return
                            else:
                                for x in xrange(0, len(lines)):
                                    self.talk(dataDict['where'], lines[x])
                                return

                self.talk(dataDict['where'], dataDict['who'] + ": You are not in any projects")
        else:
            self.talk(dataDict['where'], dataDict['who'])

    #r2bot: limit 1234
    def setLimit(self, dataDict):
        limitStr = dataDict['data'].split(' ')[2]
        if(limitStr.isdigit()):
            limit = int(limitStr)
            if(limit > 0 and limit < 30):
                self.lineLimit = limit
            else:
                self.talk(dataDict['where'], "Can only print 30 lines at most")
        else:
            self.talk(dataDict['where'], "Not a digit")



    def getCommand(self, data):
        return data.split(' ')[1]

    def listProjects(self, dataDict):
        projlist = []
        for projname, proj in self.projects.iteritems():
            projlist.append(projname)
        self.talk(dataDict['where'], str(projlist))

    #r2bot: info proj1
    def projectInfo(self, dataDict):
        pname = dataDict['data'].split(' ')[2]
        for projname, proj in self.projects.iteritems():
            if(projname == pname):
                self.talk(dataDict['where'], "Name: " + proj.name)
                self.talk(dataDict['where'], "Path: " + proj.filepath)
                self.talk(dataDict['where'], "Users: " + str(proj.users))
                return
        self.talk(dataDict['where'], "Project not found")

    #r2bot: closeproject proj1
    def closeProject(self, dataDict):
        pname = dataDict['data'].split(' ')[2]
        for projname, proj in self.projects.iteritems():
            if(projname == pname):
#self.projects.remove(projname)
                proj.close()
                del self.projects[projname]
                self.talk(dataDict['where'], "Project " + proj.name + " closed")
                return
        self.talk(dataDict['where'], "Project not found")

    #r2bot join channel
    def join(self, dataDict):
        chan = dataDict['data'].split(' ')[2]
        print("Channel: " + chan)
        self.joinChan(chan)

    def interpret(self, who, where, data, mtype):
        print("\033[93m[{bn}>] Interpreting {s} of {mt} from {u} in channel {wh}\033[0m"\
                .format(bn=self.name, s=data, mt=mtype, u=who, wh=where))
        if(self.hasLeader(data)):
            command = self.getCommand(data)
            dataDict = self.constructDict(who, where, data, self)
            print("Command: " + command + " extracted")
            if(command.lower() == 'joinproject'):
                self.joinProject(dataDict)
            elif(command.lower() == 'addproject'):
                self.addProject(dataDict)
            elif(command.lower() == 'listprojects'):
                self.listProjects(dataDict)
            elif(command.lower() == 'projectinfo'):
                self.projectInfo(dataDict)
            elif(command.lower() == 'closeproject'):
                self.closeProject(dataDict)
            elif(command.lower() == 'setlimit'):
                self.setLimit(dataDict)
            elif(command.lower() == 'join'):
                self.join(dataDict)
            else:
                self.issueCommand(dataDict)

    def listen(self):
        while True:
            try:
                data = self.conn.recieve();
                print("\033[92m[<]{n}: {d}\033[0m".format(n=self.name, d=data))
            except UnicodeDecodeError:
                print("Unicode is evil")

            for line in data.splitlines():
                if 'PING' == line.split()[0]:
                    self.conn.pong(line.split()[1])
                elif 'PRIVMSG' in line:
                    dataDict = MessageHandler().parse(line)
                    self.interpret(
                            dataDict['user'],
                            dataDict['channel'],
                            dataDict['data'],
                            dataDict['mtype'])


r2 = Bot()
r2.run()
