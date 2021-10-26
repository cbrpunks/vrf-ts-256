import { prove, keygen } from './index'
import { randomBytes } from 'crypto'

const msg = '03173a5265d3b81d9f264155e5e59881023d5d544f76ed3449aecd4544a53396'
const secretKey = 'cda5c4175025a35990af1dcf8d0272a207433c88543f2472fddff05dd3579ed7'

const pair = keygen(secretKey)
console.log(prove(pair.secret_key, msg))

/*const pair = keygen()
const pair2 = keygen()


console.log(pair)
console.log(pair2)*/