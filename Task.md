#Task overview
Create a lighter signer that runs natively in .net (C#)
Do an intial deep dive into the current go implementation available at https://github.com/elliottech/lighter-go 
We do not need to follow the exact same flow (i.e., it does not need to be an exact port) but we do need to be able to sign messages that allow us to query balances, positions, orders as well as place orders, cancel orders, and do sub account transfers
Keep a seperate file to keep track of your progress

##Hard Rules
Never upload or commit the content of the APIKEY file
Never read the content of the APIKEY file - the test app descripbed below may read the file and store the values in memory
Never log the content of the APIKEY file
Never log any API Key data

##Project structure
The project should be written as a C# console application
Use seperate files and classes for seperation of concern
Keep the project tidy so that once the test app passes we can easly move the signing code out and into a production application - this will be manual copy paste

##Hard Stops
Stop if you find yourself going in circles
Stop if you are needing to use reflection
Stop if you are following generally poor coding practices
Stop if there is any ambiguety around the goal of the task

##Test app
The console project should be a test app with a folder for the signing code and classes. Use all appropriate clean code principles for the singing code.
The test app should be able to retrieve balances and positions. When retrieving data only extract the necessary data to complete the goal. Other collections can be displayed as a simple count. There is no need to actually display the content of the balances / orders.
Use only rest requests. There is no need to do any socket impementation
The test app also needs to be able to place and cancel an order. The parameters can be hard coded to place a single limit order to buy 10 XRP at a price of $1. The app should simply output the message it is going to send and message it got back indicating success or failure.

The test app may read the API key data from the APIKEY file but you may NOT examin that file. You should write the test app to assume the APIKEY file structure is as follows
Public Key: XXX
Private Key: XXX
Account Index: XXX

L1 Address: XXX
Key Index: XXX

##Goal
1. Retrieve list of balances and output the count
2. Place limit order as per above and output the orderId
3. Retrieve list of orders and output the count
4. Note that order Id of the placed order is in the list of open orders received (use the OrderId supplied by the exchange)
5. Cancel the limit order that was placed (use the OrderId supplied by the exchange)
6. Retrieve list of orders and output the count
7. Note that order Id of the placed order is no longer in the list of open orders received
