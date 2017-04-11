

// SplitCommit/src/split-commit/split-commit-rec.h
#include "split-commit/split-commit-rec.h"
#include "split-commit/split-commit-snd.h"

// SplitCommit/libs/libOTe/cryptoTools/Network/Channel.h
#include "cryptoTools/Network/Channel.h"


void tutorial_commit100()
{

    int num_commits = 100;
    std::string default_ip_address("localhost");

    // These two containers will hold the sender's commitment data. 
    // In this example, the committed values are random and chosen by the 
    // protocol.
    std::array<BYTEArrayVector, 2> send_commit_shares{
        BYTEArrayVector(num_commits, CODEWORD_BYTES),
        BYTEArrayVector(num_commits, CODEWORD_BYTES)
    };

    // This container will hold the reciever's commitment data.
    BYTEArrayVector rec_commit_shares(num_commits, CODEWORD_BYTES);


    // These psudorandom number generators will provide the required randomness
    osuCrypto::PRNG send_rnd(osuCrypto::ZeroBlock), rec_rnd(osuCrypto::OneBlock);

    // IOService provides the workers to perform networking.
    osuCrypto::IOService ios;

    // EndPoints are help us create sockets (channels). Each pair
    // of parties will hold and two endpoints
    osuCrypto::Endpoint 
        send_end_point(ios, default_ip_address, 43701, osuCrypto::EpMode::Server, "ep"),
        rec_end_point(ios, default_ip_address, 43701, osuCrypto::EpMode::Client, "ep");


    SplitCommitSender commit_snd(128);
    SplitCommitReceiver commit_rec(128);

    std::thread thrd = std::thread([&]() {

        // create a new channel (socket) to communicate. 
        osuCrypto::Channel send_channel = send_end_point.addChannel("string_channel", "string_channel");
       
        // initialize the base OTs
        commit_snd.ComputeAndSetSeedOTs(send_rnd, send_channel);

        // commit to rnadom values
        commit_snd.Commit(send_commit_shares, send_channel);

        commit_snd.Decommit(send_commit_shares, send_channel);

        send_channel.close();
    });

    {
        // create a new cahnnel (socket) to communicate. 
        osuCrypto::Channel rec_channel = rec_end_point.addChannel("string_channel", "string_channel");

        // initialize the base OTs
        commit_rec.ComputeAndSetSeedOTs(rec_rnd, rec_channel);

        //Test that we can commit multiple times
        if (commit_rec.Commit(rec_commit_shares, rec_rnd, rec_channel) == false)
        {
            throw std::runtime_error("bad decommitment");
        }
    }

    thrd.join();
}


int main(int argc, char** argv)
{

    tutorial_commit100();


}