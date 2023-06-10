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
logic started_1 = 0;
logic[3:0] i = 0;
//logic [2:0] j = 0;
logic [2:0] e = 0;
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
logic [3:0] wordsout = 8;
logic reset_n_temp1 = 1;
logic reset_n_temp2 = 1;
logic [5:0]num_of_words = 16;
enum logic [2:0] {IDLE, PHASE1, PHASE2, PHASE3, PHASE4, PHASE5} phase;
logic [ 4:0] state;
logic [2:0]j  = 0; //determine the length of j [used for reading data in]
// by first determining the number of words that we will receive as output from the hashing device

//number of word cycles to be determined

//number of word-cycles = input /256 * 4
logic[4:0] word_cyclesP1 = 8;
//word cycles is a constant value based on the number of words that we are reciving as an input in each cycle.
logic [31:0] hout[num_nonces];
//may be unecessary logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [2:0]p1h[31:0]; //this is the (constant) output of the first phase
logic [2:0]p2h[31:0]; //this is the temporary output of the second phase used to compute the output of the third phase
logic [3:0]message2[31:0] ;
logic [31:0] outvals[2:0][3:0];//first the i value, then the j value for output //this will take a huge number of registers.
logic start1;
logic start2;
logic start3;
logic [15:0] throwAway1, throwAway2;


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
(.clk(clk), .reset_n(reset_n_temp1), .start(start1), .message_addr(message_addr), .output_addr(output_addr), .done(done1), 
.mem_clk(mem_clk), .mem_we(we1), .mem_addr(mem_addr1), .mem_write_data(temp_Mem1), .mem_read_data(mem_read_data1));


//phase 2 will be offset by 32*15 memory adress slots
//start 2 only becomes a high value when the first phase is done computing

SHA256_PHASE2 #(.NUM_OF_WORDS(3)) SHA2 
(.clk(clk), .reset_n(reset_n_temp2), .start(start2), .message_addr(message_addr), .output_addr(output_addr), 
.done(done2), .mem_clk(throwAway1), .mem_we(we2), .mem_addr(mem_addr2), .mem_write_data(temp_Mem2), .mem_read_data(mem_read_data2), 
.hvalues(p1h), .Nonce(i));
//only two instances should be required
//simplified_sha256 #(.NUM_OF_WORDS(8)) SHA3 
//(clk(clk), resset_n_temp2(reset_n), start3(start), message_addr(message_addr), output_addr(output_addr), done1(done), 
//mem_clk(mem_clk), we1(mem_we), mem_addr1(mem_addr), temp_Mem1(mem_write_data), mem_read_data1(mem_read_data));


//only two SHA256 instantiations should be required here


//instantiate a number of simplified sha instances in order to calculate the correct output.
always_ff @(posedge clk, negedge reset_n) begin
	if (!reset_n) begin //negative edge reset value
		reset_n_temp1 <= 0;
		reset_n_temp2 <= 0;
		i <=0;
		e<=0;
		j <=0;
		
		phase <= IDLE;
	end 
	
	else
	case(phase)
	IDLE:
	begin
	e <=0;
	i <= 0;
	mem_write_data <= 0;
	reset_n_temp2 = 1;
	start1 <= start;
	j <= 0;
	if(start)
	begin
	phase <= PHASE1;
	mem_read_data1 <= mem_read_data;
	mem_addr <= mem_addr1;
	end
	end //end of IDLE 
	
	PHASE1:
	begin
	mem_write_data <= 0;
	
	e <=0;
	i <=0;
	start1 <= start;
	mem_read_data1 <= mem_read_data;
	mem_addr <= mem_addr1;
	if(we1) //if memory write is enabled then one data value will be read every cycle. Before this no computation can be done
	begin
	//we only want one read to be carried out every cycle. For loops/while loops will not be sufficient here
		p1h[j] <= tempMem1;
		j <= j + 1;
	end
	else
	begin
		j <= 0;
	end
	if(done1) //once all of the data has been collected (see calculation of word cycles above) mve on to phase 2
	begin
		j<= 0;
		phase <= PHASE2;
		start2 <= 1;
	end
	end //end of PHASE1
	
	PHASE2:
	begin
	mem_write_data <= 0;

	e <=0;
	i <=0;
	//first we will trys the serial implementation
	mem_addr <= mem_addr2;
	mem_read_data2 <=mem_read_data;
	reset_n_temp <= 0; 
	if(we2)
		begin
		message2[j] <= tempMem2;
		j <= j + 1;
		end
	else
	begin
		j <=0;
	end
	if(done2) //this should be 7 at the time of execution
		begin
			for (int m = 3; m < 15; m++) 
			begin
					message2[m] = 32'h00000000; //first append the required zeros to feed the SHA 2 output 
					//back into the first SHA (this would be done internally by the SHA algorithm anyways
			end
			j <= 0;
			phase <= PHASE3;
			mem_read_data1 <= message2[j];
			reset_n_temp <= 1;
			
			
		end
		end //end of PHASE2
	PHASE3: //need extra waiting steps
	begin
		mem_write_data <= 0;

		e <=0;
		i <=0;
		start1 <= 1;
		phase <= PHASE4;
		j <= mem_addr1;
		mem_read_data1 <= message2[j];
		reset_n_temp2 <= 0;
	end //end of PHASE3
	PHASE4:
	begin
		mem_write_data <= 0;

		j<= mem_addr1;
		e <=0;
		i <=0;
		mem_read_data1<= message2[j];
		start1 <= 0;
		reset_n_temp2 <= 1;
		if(we1)
		begin
			outvals[e][i] <= tempMem1;
			e <= e +1;
		end
		if(done1)
		begin
			i <= i + 1;
			phase <= PHASE2; //cycle back to phase 2 and now calculate the next set of values
			e <= 0;
		end
		if(i == num_nonces-1)
		begin
			phase <= PHASE5;
			i <= 0;
			e <=0;
		end
		end //end of PHASE4
	PHASE5:
	begin
	
	j <=0;
	mem_write_data <= outvals[e][i];
	e <= e + 1;
	
	if(e >= wordsout-1) //when e = 7
	begin
		e <=0; //set e to be 0 on the next cycle
		i <= i + 1;
	end
	if( i == num_nonces -1 & e == wordsout-1)
	begin
		i <= 0;
		e <=0;

		phase <= IDLE;
	end
		
	end //end of PHASE 5
	default:
	begin
	j <= 0;
	e <=0;
	i <= 0;
	end
	endcase
end
assign done = (phase == IDLE);
assign mem_we = (phase == PHASE5);
endmodule
