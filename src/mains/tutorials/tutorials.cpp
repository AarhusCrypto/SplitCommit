

// SplitCommit/src/split-commit/split-commit-rec.h
#include "split-commit/split-commit-rec.h"
#include "split-commit/split-commit-snd.h"

// SplitCommit/libs/libOTe/cryptoTools/Network/Channel.h
#include "cryptoTools/Network/Channel.h"


void tutorial_commit10()
{
	int input_bit_size = 128;
	int num_commits = 10;
	std::string default_ip_address("localhost");


	// initialize our commting objects
	SplitCommitSender commit_snd(input_bit_size);
	SplitCommitReceiver commit_rec(input_bit_size);

	// These two containers will hold the sender's commitment data. 
	// In this example, the committed values are random and chosen by the 
	// protocol.
	std::array<BYTEArrayVector, 2> send_commit_shares{
		BYTEArrayVector(num_commits, commit_snd.cword_bytes),
		BYTEArrayVector(num_commits, commit_snd.cword_bytes)
	};

	// This container will hold the reciever's commitment data.
	BYTEArrayVector rec_commit_shares(num_commits, commit_snd.cword_bytes);

	// These psudorandom number generators will provide the required randomness
	osuCrypto::PRNG send_rnd(osuCrypto::ZeroBlock), rec_rnd(osuCrypto::OneBlock);

	// IOService provides the workers to perform networking.
	osuCrypto::IOService ios;

	// EndPoints are help us create sockets (channels). Each pair
	// of parties will hold and two endpoints
	osuCrypto::Endpoint
		send_end_point(ios, default_ip_address, 43701, osuCrypto::EpMode::Server, "ep"),
		rec_end_point(ios, default_ip_address, 43701, osuCrypto::EpMode::Client, "ep");


	std::thread thrd = std::thread([&]() {

		// create a new channel (socket) to communicate. 
		osuCrypto::Channel send_channel = send_end_point.addChannel("string_channel", "string_channel");

		// initialize the base OTs
		commit_snd.ComputeAndSetSeedOTs(send_rnd, send_channel);

		// commit to rnadom values
		commit_snd.Commit(send_commit_shares, send_channel);

		// lets recover the actual values committed to in the first two commitments.
		std::vector<uint8_t>
			value0(input_bit_size / 8),
			value1(input_bit_size / 8);

		// the real value is the XOR of the two shares. Here we assume the input size is 128 bits.
		XOR_128(value0.data(), send_commit_shares[0][0], send_commit_shares[1][0]);
		XOR_128(value1.data(), send_commit_shares[0][1], send_commit_shares[1][1]);

		// perform some homomorphic operations. Here, we are
		// making the first commitment be the XOR sum of itself and 
		// the second commitment.
		std::array<BYTEArrayVector, 2> homomorphic_send_commit_shares{
			BYTEArrayVector(1, commit_snd.cword_bytes),
			BYTEArrayVector(1, commit_snd.cword_bytes)
		};
		XOR_CodeWords(homomorphic_send_commit_shares[0][0], send_commit_shares[0][0], send_commit_shares[0][1]);
		XOR_CodeWords(homomorphic_send_commit_shares[1][0], send_commit_shares[1][0], send_commit_shares[1][1]);

		// Lets compute the new value that is stored at the first position.
		std::vector<uint8_t> temp(input_bit_size / 8);
		XOR_128(temp.data(), homomorphic_send_commit_shares[0][0], homomorphic_send_commit_shares[1][0]);

		// For sake of example, lets check that we get the extected value.
		for (int i = 0; i < temp.size(); ++i) {
			if (temp[i] != (value0[i] ^ value1[i])) {
				throw std::runtime_error("Homomorphic operation incorrect...");
			}
		}

		// Now lets print to the screen the values we are committed to
		for (int i = 0; i < num_commits; ++i) {
			// compute the committed value
			XOR_128(temp.data(), send_commit_shares[0][i], send_commit_shares[1][i]);

			std::cout << "sender's value[" << i << "] = ";

			for (int j = 0; j < temp.size(); j++) {
				std::cout << std::hex << std::setw(2) << std::setfill('0') << int(temp[j]);
			}

			std::cout << std::endl << std::dec;
		}

		// Lets decommit to the XOR of the first two items.
		commit_snd.Decommit(homomorphic_send_commit_shares, send_channel);

		// Now decommit to all of them.
		commit_snd.Decommit(send_commit_shares, send_channel);

		// We can also decommit to many messages in a more efficient way than with Decommit(...).
		// This method is known as batch decommit. It is more efficient in that less data is 
		// send but also requires 3 rounds of communication as opposed to 1. 
		commit_snd.BatchDecommit(send_commit_shares, send_channel);

	});


	{
		// Create a new cahnnel (socket) to communicate. 
		osuCrypto::Channel rec_channel = rec_end_point.addChannel("string_channel", "string_channel");

		// Initialize the base OTs
		commit_rec.ComputeAndSetSeedOTs(rec_rnd, rec_channel);

		//Test that we can commit multiple times
		if (commit_rec.Commit(rec_commit_shares, rec_rnd, rec_channel) == false) {
			throw std::runtime_error("bad commitment check, other party tried to cheat.");
		}

		// Perform some homomorphic operations. Here, we are making the first 
		// commitment be the XOR sum of itself and the second commitment.
		BYTEArrayVector homomorphic_rec_commit_shares(1, commit_snd.cword_bytes);
		XOR_CodeWords(homomorphic_rec_commit_shares[0], rec_commit_shares[0], rec_commit_shares[1]);

		// lets decommit to the homomorphic value
		BYTEArrayVector homomorphic_result_values(1, commit_rec.msg_bytes);
		if (commit_rec.Decommit(homomorphic_rec_commit_shares, homomorphic_result_values, rec_channel) == false) {
			throw std::runtime_error("bad homomorphic commitment check, other party tried to cheat.");
		}


		// Now lets decommit to all of the values.
		BYTEArrayVector result_values(num_commits, commit_rec.msg_bytes);
		if (commit_rec.Decommit(rec_commit_shares, result_values, rec_channel) == false) {
			throw std::runtime_error("bad decommitment check, other party tried to cheat.");
		}

		// Now lets print to the screen the values we are committed to
		for (int i = 0; i < num_commits; ++i) {
			std::cout << "receiver's value[" << i << "] = ";

			for (int j = 0; j < result_values.entry_size(); j++) {
				std::cout << std::hex << std::setw(2) << std::setfill('0') << int(result_values[i][j]);
			}

			std::cout << std::endl << std::dec;
		}

		// We can also decommit to many messages in a more efficient way than with Decommit(...).
		// This method is known as batch decommit. It is more efficient in that less data is 
		// send but also requires 3 rounds of communication as opposed to 1. 
		if (commit_rec.BatchDecommit(rec_commit_shares, result_values, rec_rnd, rec_channel) == false) {
			throw std::runtime_error("bad batch decommitment check, other party tried to cheat.");
		}
	}

	thrd.join();
}


void FullTest1() {

	int num_commits = 1 << 24;
	SplitCommitSender commit_snd(1);
	SplitCommitReceiver commit_rec(1);
	osuCrypto::IOService ios(0);

	//std::thread ret_snd = std::thread([&]() {

	osuCrypto::Endpoint send_end_point(ios, "localhost:1212", osuCrypto::EpMode::Server, "s");
	osuCrypto::PRNG send_rnd(osuCrypto::ZeroBlock);

	osuCrypto::Channel send_channel = send_end_point.addChannel("bit_channel", "bit_channel");
	send_channel.waitForConnection();
	commit_snd.ComputeAndSetSeedOTs(send_rnd, send_channel);
	std::array<BYTEArrayVector, 2> send_commit_shares{
		BYTEArrayVector(num_commits, commit_snd.cword_bytes),
		BYTEArrayVector(num_commits, commit_snd.cword_bytes)
	};
	osuCrypto::Timer timer;

	//Test that we can commit multiple times
	commit_snd.Commit(send_commit_shares, send_channel);

	timer.setTimePoint("commit");
	//Test BatchDecommit
	commit_snd.Decommit(send_commit_shares, send_channel);

	timer.setTimePoint("decommit");


	commit_snd.BatchDecommit(send_commit_shares, send_channel);
	timer.setTimePoint("batch decommit");
	std::cout << timer << std::endl;

	send_channel.close();
	//});
}
void FullTest2() {
	//{
	int num_commits = 1 << 24;
	SplitCommitSender commit_snd(1);
	SplitCommitReceiver commit_rec(1);
	osuCrypto::IOService ios(0);

	osuCrypto::Endpoint rec_end_point(ios, "localhost:1212", osuCrypto::EpMode::Client, "s");
	osuCrypto::PRNG rec_rnd(osuCrypto::ZeroBlock);

	osuCrypto::Channel rec_channel = rec_end_point.addChannel("bit_channel", "bit_channel");
	commit_rec.ComputeAndSetSeedOTs(rec_rnd, rec_channel);
	rec_channel.waitForConnection();
	BYTEArrayVector rec_commit_shares(num_commits, commit_snd.cword_bytes);

	osuCrypto::Timer timer;


	//Test that we can commit multiple times
	(commit_rec.Commit(rec_commit_shares, rec_rnd, rec_channel));

	timer.setTimePoint("commit *");
	BYTEArrayVector tmp(BITS_TO_BYTES(num_commits), 1);

	(commit_rec.Decommit(rec_commit_shares, tmp, rec_channel));
	timer.setTimePoint("decommit");
	//Test BatchDecommit
	(commit_rec.BatchDecommit(rec_commit_shares, tmp, rec_rnd, rec_channel));
	timer.setTimePoint("batch decommit");

	std::cout << timer << std::endl;

	rec_channel.close();
}

//ret_snd.join();

//}
int main(int argc, char** argv)
{
	if (argc == 1) tutorial_commit10();
	else if (argc == 2) FullTest1();
	else FullTest2();
}