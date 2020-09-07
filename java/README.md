# jGLOME
**This is not an officially supported Google product.**

This module contains a Java implementation for the GLOME
protocol.

## Usage

Let's say Alice and Bob want to establish a communication. Then both parties
should know their peer's public key. This is an example of how Alice can use 
the Glome object to generate a tag:

```Java
import com.google.jglome.Glome;
import com.google.jglome.Glome.GlomeBuilder;

public class Main {

  public void sendMsgToBob() {
    // Generates a Glome object for Alice with Bob's public key `BobPublicKey` 
    // and minimum length of Bob's tag - 32.
    Glome AliceManager = new GlomeBuilder(BobPublicKey, 32).build();

    // Generates a tag with `msg` message. Considering that this message 
    // is the first to be sent to Bob from Alice, the counter is set to 0.
    byte[] tag = AliceManager.generateTag(msg, 0);
    
    // Post-processing code block.
  }

}
```

Then Alice should send Bob both `msg`, `tag` and Alice's public key.
As soon as the information is received by Bob, the following can be done 
to verify it:

```Java
import com.google.jglome.Glome;
import com.google.jglome.Glome.GlomeBuilder;
import com.google.jglome.Glome.WrongTagException;

public class Main {

  public void sendMsgToBob() {
    // Generates a Glome object for Bob with Alice's public key `AlicePublicKey` 
    // and minimum length of Alice's tag - 32.
    Glome BobManager = new GlomeBuilder(AlicePublicKey, 32).build();

    // Checks if the received tag `tag` matches the received message `msg` and
    // a number of messages which have been sent from Alice to Bob - 0.
    try {
      BobManager.checkTag(tag, msg, 0);
    } catch (WrongTagException e) {
      // Handle the exception.
    }
    
    // Post-processing code block.
  }

}
```

Please see the source-code for more details.

## Keys

The library by default generates an ephemeral key but can be instructed to use 
a given private key as well. If you want to use a predefined key-pair you can
create a Glome object in the following way:

```Java
import com.google.jglome.Glome;
import com.google.jglome.Glome.GlomeBuilder;

public class Main {

  public void GlomeFromKeys() {
    // Generates a Glome object for Bob with Alice's public key `AlicePublicKey`, 
    // Bob's private key `BobPrivateKey` and minimum length of Alice's tag `32`.
    Glome BobManager = new GlomeBuilder(AlicePublicKey, 32)
      .setPrivateKey(BobPrivateKey)
      .build();
    
    // Post-processing code block.
  }

}
```

If you would like the keys to be generated, please see the previous section.

## Building 

### Requirements

-   Java >= 8
-   Tink > 1.4.0

### Instructions

jGLOME is built using [Maven](https://maven.apache.org/). To compile the project,
run the following from the root directory:

`mvn compile`

To run the tests use:

`mvn test`
