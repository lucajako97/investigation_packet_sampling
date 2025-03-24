# MODULES and PACKAGES
import numpy as numpy
from Kitsune import Kitsune
from scipy.stats import norm
from matplotlib import pyplot as plt
# Configures KitNET and Kitsune
# Maximum size for each autoencoder in the ensemble layer
maxAE = 10
# Number of instances used to learn the feature mapping
FMgrace = 5000
# Number of instances used to train the anomaly detector
ADgrace = 50000
# Instanciates Kitsune and its
RMSEs = []
# ToDo : Sets the features number and the feature vector -> len(featureVector)
# Place here the feature extractor in order to retrieve the feature vector that will be fed to the neural network
featuresNumber = 0
features = []
kitsune = Kitsune(featuresNumber,maxAE,FMgrace,ADgrace)
print("\033[38;5;214mKitNET 🦊\033[0m")
print("\033[90mFeeding the neural networks with the features...\033[0m\n")
# ToDo : Replace <True> with the desired exit condition
while True:
    # Computes the RMSE for the given feature vector
    rmse = kitsune.process_featureVector(features)
    if rmse == -1:
        break
    RMSEs.append(rmse)
# Visualizes the output of the neural network
# Fit the RMSE scores to a log-normal distribution
benignSample = numpy.log(RMSEs[FMgrace+ADgrace+1:100000])
logProbs = norm.logsf(numpy.log(RMSEs), numpy.mean(benignSample), numpy.std(benignSample))
plt.figure(figsize=(10,5))
fig = plt.scatter(range(FMgrace+ADgrace+1,len(RMSEs)),RMSEs[FMgrace+ADgrace+1:],s=0.1,c=logProbs[FMgrace+ADgrace+1:],cmap='RdYlGn')
plt.yscale("log")
plt.title("Anomaly Scores from Kitsune's Execution Phase")
plt.ylabel("RMSE (log scaled)")
plt.xlabel("Time elapsed [min]")
figbar=plt.colorbar()
figbar.ax.set_ylabel('Log Probability\n ', rotation=270)
plt.show()