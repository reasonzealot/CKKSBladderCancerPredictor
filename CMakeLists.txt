cmake_minimum_required(VERSION 3.13)

project(BLADDER_CANCER)


set(CMAKE_CXX_FLAGS "-Wall")
set(CMAKE_CXX_STANDARD 17)



# Import Microsoft SEAL

find_package(SEAL 4.1.1 EXACT REQUIRED
              PATHS /usr/local # for Linux
            #   PATHS /opt/homebrew/Cellar # for Mac OS
            ) 


set(BLADDER_CANCER_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)

add_executable(bladder_cancer
	${BLADDER_CANCER_SOURCE_DIR}/main.cpp
	${BLADDER_CANCER_SOURCE_DIR}/client.cpp
		${BLADDER_CANCER_SOURCE_DIR}/server.cpp
		${BLADDER_CANCER_SOURCE_DIR}/utils.cpp)
                
                    
if(TARGET SEAL::seal)
    target_link_libraries(bladder_cancer SEAL::seal)
elseif(TARGET SEAL::seal_shared)
    target_link_libraries(bladder_cancer SEAL::seal_shared)
else()
    message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")

endif()



                

