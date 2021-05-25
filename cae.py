import secrets
import string
import numpy as np
import math
from matplotlib import pyplot as plt
import os
import imageio


f = open('InputFile.txt')           #входное сообщение
len_text = len(f.read())            #длина входного сообщения
f.seek(0)
block_size = 8                      #переменная для определения размера блока
operating_mode_of_the_machine = 2   #режим работы автомата(1-работа с битами, 2-работа с байтами)

def generate_pass(length):                                                                  # length - длина ключа
    letters_and_digits = string.ascii_letters + string.digits                               # формирование алфавита
    crypt_rand_string = ''.join(secrets.choice(letters_and_digits) for i in range(length))  # генерация
    return crypt_rand_string                                                                # возврат значения

def isInt(n):#можно убрать
    return int(n) == float(n)

def byte_mode_param(mode, f):#можно убрать 
    if mode == 1:
        for c in range(1, 100):
            for n in range(3, 128):
                if ((n-2)**2)*c == f:
                    n_out = n
                    c_out = c
    if mode == 2:
        for c in range(1, 100):
            for n in range(3, 128):
                if ((n-2)**2)*c == f-(n-4)**2:
                    n_out = n
                    c_out = c
    return n_out, c_out


def block_parameters(encryption_mode, len_text, n):
    if encryption_mode == 1:
        ny = math.ceil(math.sqrt(len_text))
        nx = math.ceil(math.sqrt(len_text))*n
    if encryption_mode == 2:
        ny = math.ceil(math.sqrt(len_text))
        nx = math.ceil(math.sqrt(len_text))
    #else:
    return nx, ny

def splitting_into_packages(input_file, encryption_mode):
    nx, ny = block_parameters(encryption_mode, len_text, block_size)
    message_blocks = np.zeros((nx+2, ny+2),dtype = int)
    variable_counter = 0
    nx+=2
    ny+=2
    if encryption_mode == 1:
        for y in range(1, ny-1):
            for x in range(1, nx-1, block_size):
                if variable_counter < len_text:
                    sim = format(ord(input_file.read(1)), 'b')
                    if len(sim) < 8:
                        sim = '0'*(8-len(sim)) + sim
                    for bit_i in range(block_size):
                        message_blocks[x+(bit_i-1)][y] = int(sim[bit_i])
                    #input_file.seek(1)
                variable_counter+=1

    if encryption_mode == 2:
        for y in range(1, ny-1):
            for x in range(1, nx-1):
                if variable_counter < len_text:
                    message_blocks[x][y] = ord(input_file.read(1))
                    #input_file.seek(1)
                variable_counter+=1
    f.seek(0)
    return message_blocks

def field_closure_function(message_blocks, encryption_mode):
    nx, ny = block_parameters(encryption_mode, len_text, block_size)
    nx+=2
    ny+=2
    message_blocks[:,0] = message_blocks[:,ny-2]
    message_blocks[:,ny-1] = message_blocks[:,1]
    message_blocks[0,:] = message_blocks[nx-2,:]
    message_blocks[nx-1,:] = message_blocks[1,:]
    return message_blocks

def moore_neighborhood_distribution(Moore_block, time_sim):
    Moore_block[0][0] = time_sim[0]
    Moore_block[1][0] = time_sim[1]
    Moore_block[2][0] = time_sim[2]
    Moore_block[2][1] = time_sim[3]
    Moore_block[2][2] = time_sim[4]
    Moore_block[1][2] = time_sim[5]
    Moore_block[0][2] = time_sim[6]
    Moore_block[0][1] = time_sim[7]

def block_encryption(message_blocks, password, encryption_mode):
    Moore_block = np.zeros((3,3), dtype=int)
    nx, ny = block_parameters(encryption_mode, len_text, block_size)
    nx+=2
    ny+=2
    message_blocks = field_closure_function(message_blocks, encryption_mode)
    for i in range(len(password)):
        time_sim = format(ord(password[i]), 'b')
        if len(time_sim) < 8:
            time_sim = '0'*(8-len(time_sim)) + time_sim
        moore_neighborhood_distribution(Moore_block, time_sim)
        for y in range(ny-2):
            for x in range(nx-2):
                message_blocks[x+1][y+1] = int(message_blocks[x+1][y+1])^(int(message_blocks[x][y])*Moore_block[0][0])^(int(message_blocks[x+1][y])*Moore_block[1][0])^(int(message_blocks[x+2][y])*Moore_block[2][0])^(int(message_blocks[x+2][y+1])*Moore_block[2][1])^(int(message_blocks[x+2][y+2])*Moore_block[2][2])^(int(message_blocks[x+1][y+2])*Moore_block[1][2])^(int(message_blocks[x][y+2])*Moore_block[0][2])^(int(message_blocks[x][y+1])*Moore_block[0][1])
                message_blocks = field_closure_function(message_blocks, encryption_mode)
        #save_layer_as_image(message_blocks, i)
    return message_blocks

def block_decryption(message_blocks, password, encryption_mode):
    Moore_block = np.zeros((3,3), dtype=int)
    nxy = np.shape(message_blocks)
    nx = nxy[0]
    ny = nxy[1]
    for i in range(len(password)-1, -1, -1):
        time_sim = format(ord(password[i]), 'b')
        if len(time_sim) < 8:
            time_sim = '0'*(8-len(time_sim)) + time_sim
        moore_neighborhood_distribution(Moore_block, time_sim)
        for y in range(ny-3, -1, -1):
            for x in range(nx-3, -1, -1):
                message_blocks[x+1][y+1] = int(message_blocks[x+1][y+1])^(int(message_blocks[x][y])*Moore_block[0][0])^(int(message_blocks[x+1][y])*Moore_block[1][0])^(int(message_blocks[x+2][y])*Moore_block[2][0])^(int(message_blocks[x+2][y+1])*Moore_block[2][1])^(int(message_blocks[x+2][y+2])*Moore_block[2][2])^(int(message_blocks[x+1][y+2])*Moore_block[1][2])^(int(message_blocks[x][y+2])*Moore_block[0][2])^(int(message_blocks[x][y+1])*Moore_block[0][1])
                message_blocks = field_closure_function(message_blocks, encryption_mode)
        save_layer_as_image(message_blocks, i)
    return message_blocks

def save_layer_as_image(layer, numberlayer):
    layer = layer.astype(float)
    fig, ax = plt.subplots()
    ax.imshow(layer)
    fig.set_figwidth(6)    #  ширина и
    fig.set_figheight(6)    #  высота "Figure"

    plt.savefig('./png/image_'+ str(numberlayer) + '.png')

def save_image_as_gif():
    png_dir = "./png/"
    images = []
    for subdir, dirs, files in os.walk(png_dir):
        for file in files:
            file_path = os.path.join(subdir, file)
            if file_path.endswith(".png"):
                images.append(imageio.imread(file_path))
    imageio.mimsave('./gif/movie.gif', images)

input_text = splitting_into_packages(f,operating_mode_of_the_machine)
password = generate_pass(16)
x = block_encryption(splitting_into_packages(f,operating_mode_of_the_machine),password,operating_mode_of_the_machine)
y = x.copy()
#password1 = "4JCaWxPq3WyUX7cI"
out = block_decryption(y,password,operating_mode_of_the_machine)

save_layer_as_image(input_text, 90)

save_image_as_gif()
#np.savetxt("EncryptedFile.txt", x.astype(str), fmt= '%')
#x = x.astype(str)
#np.save('EncryptedFile', x)
#x = x.astype(float)
#input_text = input_text.astype(float)
#out = out.astype(float)
#fig, ax = plt.subplots()

#ax.imshow(x)

#fig.set_figwidth(6)    #  ширина и
#fig.set_figheight(6)    #  высота "Figure"

