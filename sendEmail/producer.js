// producer.js

const { Queue, QueueScheduler } = require('bullmq')

// Add your own configuration here
const redisConfiguration = {
  connection: {
    host: "localhost",
    port: 6379,
    // username: "default",
    // password: "redispw"
  }
}

// Delayed jobs will only be processed if there is at least one QueueScheduler instance configured in the Queue.
// let test = new QueueScheduler('emailSchedule', redisConfiguration );

const myQueue = new Queue('emailSchedule', redisConfiguration);

async function emailSchedule(email, message, delay) {
  await myQueue.add('email', { email, message }, { delay});
}

emailSchedule("foo@bar.com", "Hello World!", 5000); // The email will be available for consumption after 5 seconds. 