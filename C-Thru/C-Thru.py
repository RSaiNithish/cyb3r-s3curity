import cv2 
import numpy as np
import matplotlib.pyplot as plt

class Cthru:
    """Cthru ("see-through") is a simple implementation of Image steganography.
    It is based on least significant bit image steganogrphy
    
    """
    def __init__(self,path):
        """Initializing the Cthru object with the image given in the path

        Args:
            path (str): path to the image
        """
        self.image = cv2.imread(path)
        self.max_size = (self.image.shape[0] * self.image[1] *3 //8)[0][0]
        
    
    def binary(self,value):
        """Converts allowed given inputs into its corresponding binary form

        Args:
            value (_type_): value that needs to be converted into binary

        Raises:
            TypeError: When the input is not of any the allowed types

        Returns:
            str/byte/list: the corresponding binary format 
        """
        type_ = type(value)
        if type_ == str:
            # In case of str the string is converted to its ASCII form and then converted to binary
            return ''.join([format(ord(i), "08b") for i in value])
            #ord will return the ASCII value and we are fromatting it into 8-bit binary
        elif type_ == bytes or type_ == np.ndarray:
            return [format(i, '08b') for i in value]
        elif type_ == int or type_ == np.uint8:
            return format(value, '08b')
        else:
            raise TypeError(f"Error:Invalid input type.\nExpected str or bytes or ndarray but recieved {type_}")
        
    def encode(self,msg):
        """Method for encoding the message into the image

        Args:
            msg (str): Messae that needs to be hidden into the image

        Raises:
            ValueError: If the message size exceeds the limit

        Returns:
            np.ndarray: The Encoded image
        """
        msg_len = len(msg)
        if msg_len > self.max_size:
            raise ValueError(f"Error: Input limit exceeded.\nExpected text size of {self.max_size} but recieved{msg_len}.")
        # Defining delimiter
        msg += '`-`'
        # Convert text to binary
        b_msg = self.binary(msg)
        i = 0
        data_len = len(b_msg)
        for values in self.image:
            for pixel in values:
                #Convert pixel values to binary
                r, g, b = self.binary(pixel)
                #Encode the data
                if i < data_len:
                    pixel[0] = int(r[:-1] +b_msg[i],2)
                    i +=1
                if i < data_len:
                    pixel[1] = int(g[:-1] + b_msg[i],2)
                    i+=1
                if i< data_len:
                    pixel[2] = int(b[:-1] + b_msg[i],2)
                    i+=1
                if i >= data_len:
                    break
        return self.image
    
    def decode(self):
        """Method for decoding the message from the image

        Returns:
            str: Decoded string
        """
        b_msg = ""
        for values in self.image:
            for pixel in values:
                r, g, b = self.binary(pixel)
                b_msg += r[-1]
                b_msg += g[-1]
                b_msg += b[-1]
                
        b_ = [b_msg[i:i+8] for i in range(0,len(b_msg),8)]
        msg = ""
        for byte in b_:
            msg += chr(int(byte,2))
            if msg[-3:] == '`-`':
                break
        
        return msg[:-3]
    
    def save(self, path = "./encoded.png"):
        """Method to save the encoded image 

        Args:
            path (str, optional): Absolute path of the image. Defaults to "./encoded.png".
        """
        cv2.imwrite(path,self.img)
        
