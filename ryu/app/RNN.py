import numpy as np
import pandas as pd
import math
import sklearn
import sklearn.preprocessing
import datetime
import os
import matplotlib.pyplot as plt
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, LSTM
from sklearn.utils import shuffle

N = 25000
def preprocessing(N):

    train_data = pd.read_csv('CIDDS-001-internal-week2.csv')
    norm = train_data[train_data['class'] == 'normal'].iloc[0:int(N/2), :]
    norm = norm.drop(columns = ['attackType', 'attackID', 'attackDescription'])

    attack = train_data[train_data['class'] == 'attacker'].iloc[0:int(N/2), :]
    attack = attack.drop(columns = ['attackType', 'attackID', 'attackDescription'])
    combined_train_data = norm.append(attack, ignore_index = True)
    train_data = shuffle(combined_train_data)
    train_data = train_data.reindex(range(0, N))
    train_data = train_data[['Src IP Addr', 'Dst IP Addr', 'Src Pt', 'Dst Pt', 'Packets', 
                             'Bytes', 'Duration', 'Proto', 'class']]
    
    # mp = {}
    # id = 0
    # for ft in train_data['Src IP Addr']:
    #     if ft not in mp:
    #         mp[ft] = id
    #         id += 1
            
    # for i, e in enumerate(train_data['Src IP Addr']):
    #     train_data['Src IP Addr'][i] = mp[e]
        
    # print("Done with Src IP Addr encoding!")

    # for ft in train_data['Dst IP Addr']:
    #     if ft not in mp:
    #         mp[ft] = id
    #         id += 1
            
    # for i, e in enumerate(train_data['Dst IP Addr']):
    #     train_data['Dst IP Addr'] = mp[e]
        
    # print("Done with Dst IP Addr encoding!")

    # mp = {}
    # id = 0
    # for ft in train_data['Flags']:
    #     if ft not in mp:
    #         mp[ft] = id
    #         id += 1
            
    # for i, e in enumerate(train_data['Flags']):
    #     train_data['Flags'] = mp[e]
        
    # print("Done with Flags encoding!")
    
    mp = {}
    id = 0
    for ft in train_data['Proto']:
        if ft not in mp:
            mp[ft] = id
            id += 1
        #['TCP  ' 'UDP  ' 'IGMP ' 'ICMP ']
        if ft is "TCP":
            mp[ft] = 6
        elif ft is "UDP":
            mp[ft] = 17
        elif ft is "IGMP":
            mp[ft] = 2
        elif ft is "ICMP":
            mp[ft] = 1
        else:
            mp[ft] = 0
            
    for i, e in enumerate(train_data['Proto']):
        train_data['Proto'] = mp[e]
        
    print("Done with Proto encoding!")
    
    return(train_data)


train_data = preprocessing(N)


def recurrentNeuralNetwork(train_data, N):
    train_x = train_data.iloc[:, 4:8]
    train_y = train_data.iloc[:, 8]

    train_x = train_x.reindex(range(0, N))
    train_y = train_y.reindex(range(0, N))

    # making the training target value numerical for the neural network
    # 0 indicates normal; 1 indicates anomaly
    for i in range(0, N):
        if train_y[i] == 'normal':
            train_y[i] = 0
            
        if train_y[i] == 'attacker':
            train_y[i] = 1

    # # train_x = np.reshape(train_x, (20000, 8, 1))
    # # test_x = np.reshape(test_x, (5000, 8, 1))

    # # Sequential model for a plain stack of layers
    # # each layer has exactly one input tensor and one output tensor

    # # LSTM = Long Short-Term Memory Layer
    # # relu = rectified linear unit activation function
    # model.add(Dense(256, input_dim = 5, activation = 'relu'))

    # # Dropout sets a fraction rate (here, 1/5) of input units to 0
    # # at each update during training; helps to prevent overfitting
    # model.add(Dropout(0.2))

    # model.add(Dense(128, activation = 'relu'))

    # model.add(Dropout(0.2))

    # # Dense = deeply connected neural network layer
    # model.add(Dense(64, activation = 'relu'))
    # model.add(Dropout(0.2))

    # model.add(Dense(16, activation = 'sigmoid'))

    # # Adam optimizer is an SGD (Stochastic Gradient Descent) method
    # # based on adaptive estimation of first-order and second-order moments
    # # picked as it is well suited for large number of data/parameters
    # opt = tf.keras.optimizers.SGD(lr = 0.01, decay = 1e-5)

    # # sparse_categorical_crossentropy calculates the crossentropy loss between
    # # labels and predictions
    # # accuracy could be improved using a different loss functions
    # # it seems as if this loss function is best for two or more label classes
    # model.compile(loss = 'categorical_crossentropy',
    #             optimizer = opt,
    #             metrics = ['accuracy'])
    
    model = Sequential()
    model.add(Dense(8, input_dim=4, activation='relu'))
    model.add(Dense(8, activation='relu'))
    model.add(Dense(1, activation='sigmoid'))
    model.compile(loss='binary_crossentropy', optimizer='adam',metrics = ['accuracy'])

    # convert to array
    train_x = np.asarray(train_x)
    train_y = np.asarray(train_y)

    # convert to tensorflow format to feed into the fit function()
    train_x = tf.convert_to_tensor(train_x, np.float32)
    train_y = tf.convert_to_tensor(train_y, np.float32)

    # feed in training and test data
    model.fit(train_x, train_y, epochs = 20, steps_per_epoch = 1000)
    
    model.save("myModel")


    print("rnn model run complete")
    return(model)

model = recurrentNeuralNetwork(train_data, N)
