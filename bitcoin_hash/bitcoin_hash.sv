module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

parameter num_nonces = 16;

logic done1;
logic done2; //done for all 3 SHA 256 instances
logic done3;
logic we1;
logic we2; //write enable for all three SHA 256 instances
logic we3;
logic [15:0] mem_addr1;
logic [15:0] mem_addr2; // input memory adress for all three SHA 256 instances
logic [15:0] mem_addr3;
logic [31:0] tempMem1;
logic [31:0] tempMem2; // output memory adress for all 3 SHA 256 instances
logic [31:0] tempMem3;
logic [31:0] mem_read_data1;
logic [31:0] mem_read_data2;
logic [31:0] mem_read_data3;




logic num_of_words[5:0] = 16;
enum logic [1:0] {PHASE1, PHASE2, PHASE3, DONE} phase;
logic [ 4:0] state;
logic j [$clog2(num_of_words)+1:0] = 0 //determine the length of j [used for reading data in]
// by first determining the number of words that we will receive as output from the hashing device

//number of word cycles to be determined

//number of word-cycles = input /256 * 4

logic[4:0] word_cyclesP1 = 15;
//word cycles is a constant value based on the number of words that we are reciving as an input in each cycle.
logic [31:0] hout[num_nonces];
//may be unecessary logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [31:0]p1h[2:0] = 0; //this is the (constant) output of the first phase
logic start2;
logic start3;


parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

//we need to repeat this process fifteen times
//can create more SHA256 to increase efficency
simplified_sha256 #(.NUM_OF_WORDS(16)) simplified_sha256_inst 
(clk(clk), resset_n(reset_n), start(start), message_addr(message_addr), output_addr(output_addr), done1(done), 
mem_clk(mem_clk), we1(mem_we), mem_addr1(mem_addr), temp_Mem1(mem_write_data), mem_read_data1(mem_read_data));


//phase 2 will be offset by 32*15 memory adress slots
//start 2 only becomes a high value when the first phase is done computing

SHA256_PHASE2 #(.NUM_OF_WORDS(3)) simplified_sha256_inst 
(clk(clk), reset_n(reset_n), start2(start), message_addr+512(message_addr), output_addr(output_addr), 
done2(done), mem_clk(mem_clk), we2(mem_we), mem_addr2(mem_addr), mem_write_data, mem_read_data2(mem_read_data), 
p1h(HValues), i(Nonce);

//instantiate a number of simplified sha instances in order to calculate the correct output.
always_ff @(posedge clk, negedge reset_n) begin
	case(phase)
	PHASE1:
	mem_addr <= mem_addr1;
	mem_read
	if(we1) //if memory write is enabled then one data value will be read every cycle. Before this no computation can be done
	begin
	//we only want one read to be carried out every cycle. For loops/while loops will not be sufficient here
		p1h[j] <= mem_write_data1;
		j <= j + 1;
	end
	if(j >= word_cycles) //once all of the data has been collected (see calculation of word cycles above) mve on to phase 2
	begin
		j<= 0;
		phase <= PHASE2;
		start2 <= 1;
	end
	
	PHASE2:
	if(mem_we)
		begin
		
	//we know that we have the complete hash for phase 1
	//this will allow us to compute all of the output hashes for phase 2 relativeley easliy.
	//we now need to feed the output values of the first round directly into the second algrothim's hash table
	


//we know that the first nineteen words are the same but the last word will change and cause an avalanche effect on the rest of the output

//we will iterate through all of the nonces

// Student to add rest of the code here






endmodule
