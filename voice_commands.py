import speech_recognition as sr
from gtts import gTTS # google text to speech 
import os # to save/open files 
from subprocess import * #running shell file

r = sr.Recognizer()
with sr.Microphone() as source:
    r.adjust_for_ambient_noise(source)
    print("Say something!")
    audio = r.listen(source, timeout=None, phrase_time_limit=5, snowboy_configuration=None)
    
print("Stop.") # limit 5 secs 
  
try: 
    text = r.recognize_google(audio, language ='en-US') 
    print("You said: ", text)
    # to write a bash file
    # f = open("command.sh", "a")
    # f.write("ls \n")
    # f.close()

    if (text.lower() == "list"):
        print("Running command: ls")
        stream = os.popen('ls')
        output = stream.read()
        print(output)

    elif (text.lower() == "list all"):
        print("Running command: ls -a")
        stream = os.popen('ls -a')
        output = stream.read()
        print(output)

    elif (text.lower() == "list long"):
        print("Running command: ls -l")
        stream = os.popen('ls -l')
        output = stream.read()
        print(output)

    elif (text.lower() == "start controller"):
        print("Running command: start controller")
        stream = os.popen('PYTHONPATH=. ./bin/ryu-manager ryu/app/simple_monitor_13.py --observe-links')
        output = stream.read()
        print(output)
        speech = gTTS(text = text.lower(), lang = 'en', slow = False)
        speech.save("voice.mp3")
        os.system("start voice.mp3")

    elif (text.lower() == "create topology"):
        print("Running command: start topology")
        stream = os.popen(
            'sudo mn --custom mesh_topo.py --topo mytopo --mac --controller=remote,127.0.0.1 --switch ovsk,protocol=OpenFlow13 --link=tc')
        output = stream.read()
        print(output)     

    elif (text.lower() == "stop controller"):
        print("Running command: ./stop")
        stream = os.popen('kill `pgrep python`')
        output = stream.read()
        print(output)

    
    else:
        print("Unknown Command!")


except: 
        print("Could not understand your audio, PLease try again !") 